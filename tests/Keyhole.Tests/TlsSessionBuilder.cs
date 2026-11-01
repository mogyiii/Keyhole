using System.Buffers.Binary;
using System.Security.Cryptography;
using Keyhole.Core.Capture.Decode;
using Keyhole.Core.Capture.Pcapng;

namespace Keyhole.Tests;

/// <summary>
/// Builds a synthetic but spec-conforming TLS 1.3 session, as a capture file with its own
/// keylog embedded.
///
/// Needed because there is no way to obtain a real keylog inside a test on Windows: every
/// TLS client .NET can drive here runs on Schannel, which ignores SSLKEYLOGFILE by design.
/// So the session is constructed — handshake, records, TCP, IP and all — from a traffic
/// secret this builder chooses.
///
/// The point is what can then be done with it. The same file is handed to Keyhole's
/// decoder and to tshark, and the two are compared. A round trip against Keyhole alone
/// would only prove it is self-consistent: a key schedule that misreads the specification
/// would encrypt and decrypt perfectly well while agreeing with nothing in the world.
/// tshark is the independent reading.
/// </summary>
internal static class TlsSessionBuilder
{
    /// <summary>TLS_AES_128_GCM_SHA256, which is what browsers negotiate most often.</summary>
    private const ushort CipherSuite = 0x1301;

    private const int KeyLength = 16;

    private static readonly byte[] ClientAddress = [10, 0, 0, 5];
    private static readonly byte[] ServerAddress = [93, 184, 216, 34];
    private const int ClientPort = 51000;
    private const int ServerPort = 443;

    /// <summary>
    /// Writes a capture of one TLS 1.3 connection carrying <paramref name="request"/> and
    /// <paramref name="response"/> as HTTP/1.1.
    /// </summary>
    /// <returns>The path to the capture file, and the keylog written into it.</returns>
    public static (string Path, string Keylog) WriteCapture(
        string request, string response, bool embedSecrets = true) =>
        WriteCapture(
            System.Text.Encoding.ASCII.GetBytes(request),
            System.Text.Encoding.ASCII.GetBytes(response),
            embedSecrets,
            alpn: "http/1.1");

    /// <summary>
    /// Writes a capture whose application payload is given as bytes, so an HTTP/2
    /// connection can be built as well as an HTTP/1.1 one.
    /// </summary>
    /// <param name="alpn">
    /// The protocol to advertise. Wireshark picks its HTTP dissector from ALPN, so an
    /// HTTP/2 payload announced as http/1.1 would be dissected as neither.
    /// </param>
    public static (string Path, string Keylog) WriteCapture(
        byte[] request, byte[] response, bool embedSecrets, string alpn) =>
        WriteCapture(request, response, embedSecrets, alpn, keyUpdateAfterFirstRecord: false);

    /// <summary>
    /// Writes a capture of one TLS 1.3 connection.
    /// </summary>
    /// <param name="keyUpdateAfterFirstRecord">
    /// When set, the server's response is split across two records with a key update
    /// between them: the second is encrypted under the next derived traffic secret, at
    /// sequence zero. Nothing on the wire announces this — the KeyUpdate message is itself
    /// encrypted under the old key — so a decoder has to try the derivation and let the
    /// AEAD tag decide. A real browser session moving tens of megabytes triggers one.
    /// </param>
    public static (string Path, string Keylog) WriteCapture(
        byte[] request,
        byte[] response,
        bool embedSecrets,
        string alpn,
        bool keyUpdateAfterFirstRecord)
    {
        var random = RandomNumberGenerator.GetBytes(32);
        var clientRandom = RandomNumberGenerator.GetBytes(32);
        var serverRandom = RandomNumberGenerator.GetBytes(32);

        // The traffic secrets a real client would have derived from the handshake. Chosen
        // here instead, which is exactly what a keylog makes possible.
        var clientSecret = RandomNumberGenerator.GetBytes(32);
        var serverSecret = RandomNumberGenerator.GetBytes(32);
        var clientHandshakeSecret = RandomNumberGenerator.GetBytes(32);
        var serverHandshakeSecret = RandomNumberGenerator.GetBytes(32);

        var suite = TlsCipherSuite.Find(CipherSuite)!;
        var clientKeys = TlsKeySchedule.FromTrafficSecret(clientSecret, suite);
        var serverKeys = TlsKeySchedule.FromTrafficSecret(serverSecret, suite);
        var clientHandshakeKeys = TlsKeySchedule.FromTrafficSecret(clientHandshakeSecret, suite);
        var serverHandshakeKeys = TlsKeySchedule.FromTrafficSecret(serverHandshakeSecret, suite);

        var keylog = string.Join('\n',
            $"CLIENT_HANDSHAKE_TRAFFIC_SECRET {Hex(clientRandom)} {Hex(clientHandshakeSecret)}",
            $"SERVER_HANDSHAKE_TRAFFIC_SECRET {Hex(clientRandom)} {Hex(serverHandshakeSecret)}",
            $"CLIENT_TRAFFIC_SECRET_0 {Hex(clientRandom)} {Hex(clientSecret)}",
            $"SERVER_TRAFFIC_SECRET_0 {Hex(clientRandom)} {Hex(serverSecret)}") + "\n";

        var path = Path.Combine(Path.GetTempPath(), $"keyhole-tls-{Guid.NewGuid():N}.pcapng");

        using (var writer = PcapngWriter.Create(path))
        {
            var adapter = writer.AddInterface(PcapngLinkType.Ethernet, "Synthetic");

            var when = new DateTimeOffset(2026, 11, 1, 12, 0, 0, TimeSpan.Zero);

            // TCP sequence numbers start at a random value in reality, and starting them
            // at something other than zero is what exercises the reassembler's base
            // handling rather than letting an off-by-one pass unnoticed.
            var clientSeq = 1_000_000u;
            var serverSeq = 7_000_000u;

            void Send(
                bool fromClient, ReadOnlySpan<byte> payload, bool syn = false, bool ack = true)
            {
                var frame = BuildFrame(
                    fromClient, payload, fromClient ? clientSeq : serverSeq, syn, ack);
                writer.WritePacket(adapter, when, frame);
                when = when.AddMilliseconds(5);

                if (fromClient)
                {
                    clientSeq += (uint)payload.Length + (syn ? 1u : 0u);
                }
                else
                {
                    serverSeq += (uint)payload.Length + (syn ? 1u : 0u);
                }
            }

            // The three-way handshake, so the reassembler learns which side is the client
            // from a SYN rather than by assumption. The client's SYN carries no ACK and
            // the server's does — which is the only thing distinguishing them, and getting
            // it wrong here once hid a real bug in the decoder.
            Send(fromClient: true, [], syn: true, ack: false);
            Send(fromClient: false, [], syn: true, ack: true);

            Send(fromClient: true, Record(22, 0x0301, ClientHello(clientRandom, alpn)));
            Send(fromClient: false, Record(22, 0x0303, ServerHello(serverRandom, alpn)));

            // The ChangeCipherSpec both sides send purely so that middleboxes see a
            // familiar shape. It is not encrypted and must not advance a sequence number —
            // a decoder that counts it gets every nonce after it wrong.
            Send(fromClient: false, Record(20, 0x0303, [1]));

            // The encrypted handshake: the server's EncryptedExtensions and Finished, then
            // the client's Finished, all under the handshake traffic secrets at their own
            // sequence numbers.
            //
            // A real TLS 1.3 connection always has these, and including them is what makes
            // this capture realistic enough to be worth comparing against another
            // implementation. They also exercise the thing the decoder has to get right
            // and cannot see: the switch to application keys, where the sequence number
            // restarts at zero.
            Send(
                fromClient: false,
                Encrypt(serverHandshakeKeys, 0, [
                    .. Handshake(8, [0x00, 0x00]),                      // EncryptedExtensions
                    .. Handshake(20, RandomNumberGenerator.GetBytes(32)) // Finished
                ],
                innerContentType: 22));

            Send(fromClient: true, Record(20, 0x0303, [1]));

            Send(
                fromClient: true,
                Encrypt(clientHandshakeKeys, 0,
                    Handshake(20, RandomNumberGenerator.GetBytes(32)),
                    innerContentType: 22));

            Send(fromClient: true, Encrypt(clientKeys, 0, request));

            if (!keyUpdateAfterFirstRecord)
            {
                Send(fromClient: false, Encrypt(serverKeys, 0, response));
            }
            else
            {
                // Split the response so the second half needs the updated key. Splitting
                // at the headers' end keeps both halves meaningful: the first carries the
                // status line, the second the body.
                var split = Math.Max(1, response.Length / 2);

                Send(fromClient: false, Encrypt(serverKeys, 0, response[..split]));

                var updated = TlsKeySchedule.FromTrafficSecret(
                    TlsKeySchedule.ExpandLabel(
                        serverSecret, "traffic upd", [], 32, suite.HashName),
                    suite);

                // Sequence restarts at zero under the new key.
                Send(fromClient: false, Encrypt(updated, 0, response[split..]));
            }

            if (embedSecrets)
            {
                writer.WriteTlsSecrets(keylog);
            }

            _ = random;
            _ = serverRandom;
        }

        if (embedSecrets)
        {
            // Placed ahead of the packets, which is where a sequential reader needs them.
            PcapngSecretsInjector.Inject(path, keylog);
        }

        return (path, keylog);
    }

    private static string Hex(byte[] bytes) => Convert.ToHexStringLower(bytes);

    /// <summary>
    /// Encrypts one TLS 1.3 record.
    ///
    /// The inner content type goes at the end of the plaintext and the associated data is
    /// the record header verbatim — both details that a decoder has to get exactly right,
    /// and both of which tshark will independently check.
    /// </summary>
    private static byte[] Encrypt(
        TlsDirectionKeys keys, ulong sequence, byte[] plaintext, byte innerContentType = 23)
    {
        // content || inner content type. No padding, which is legal.
        var inner = new byte[plaintext.Length + 1];
        plaintext.CopyTo(inner, 0);
        inner[^1] = innerContentType;

        var ciphertext = new byte[inner.Length];
        var tag = new byte[16];

        // The header has to exist before encrypting, because its length field covers the
        // ciphertext and tag and it is itself the associated data.
        var header = new byte[5];
        header[0] = 23;
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(1), 0x0303);
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(3), (ushort)(inner.Length + 16));

        var nonce = TlsKeySchedule.Nonce(keys.Iv, sequence);

        using var aes = new AesGcm(keys.Key, 16);
        aes.Encrypt(nonce, inner, ciphertext, tag, header);

        var record = new byte[5 + ciphertext.Length + tag.Length];
        header.CopyTo(record, 0);
        ciphertext.CopyTo(record, 5);
        tag.CopyTo(record, 5 + ciphertext.Length);

        return record;
    }

    private static byte[] Record(byte contentType, ushort version, ReadOnlySpan<byte> body)
    {
        var record = new byte[5 + body.Length];
        record[0] = contentType;
        BinaryPrimitives.WriteUInt16BigEndian(record.AsSpan(1), version);
        BinaryPrimitives.WriteUInt16BigEndian(record.AsSpan(3), (ushort)body.Length);
        body.CopyTo(record.AsSpan(5));
        return record;
    }

    /// <summary>
    /// A ClientHello carrying the client random that joins this connection to its keylog
    /// line, and a supported_versions extension naming TLS 1.3.
    /// </summary>
    private static byte[] ClientHello(byte[] clientRandom, string alpn)
    {
        var extensions = new List<byte>();
        extensions.AddRange(SupportedVersions(asClient: true));
        extensions.AddRange(AlpnExtension(alpn, asClient: true));

        var body = new List<byte>();
        body.AddRange([0x03, 0x03]);               // legacy_version
        body.AddRange(clientRandom);
        body.Add(0);                                // legacy_session_id: empty
        body.AddRange([0x00, 0x02]);               // cipher_suites length
        body.AddRange([0x13, 0x01]);               // TLS_AES_128_GCM_SHA256
        body.Add(1);                                // compression_methods length
        body.Add(0);                                // null compression
        body.AddRange(UInt16(extensions.Count));
        body.AddRange(extensions);

        return Handshake(1, [.. body]);
    }

    /// <summary>
    /// A ServerHello naming the suite and, in its extension, the real version.
    ///
    /// The version in the legacy field says 1.2 — which is what TLS 1.3 requires, and why
    /// a decoder that trusts it sends every 1.3 connection down the wrong key schedule.
    /// </summary>
    private static byte[] ServerHello(byte[] serverRandom, string alpn)
    {
        // ALPN belongs in EncryptedExtensions in TLS 1.3, not in the ServerHello — but
        // Wireshark accepts it from the ClientHello's offer when the handshake is
        // decryptable, which is enough for the dissector to be chosen correctly here.
        _ = alpn;

        var extensions = SupportedVersions(asClient: false);

        var body = new List<byte>();
        body.AddRange([0x03, 0x03]);               // legacy_version: deliberately 1.2
        body.AddRange(serverRandom);
        body.Add(0);                                // legacy_session_id_echo: empty
        body.AddRange([0x13, 0x01]);               // the chosen suite
        body.Add(0);                                // compression
        body.AddRange(UInt16(extensions.Length));
        body.AddRange(extensions);

        return Handshake(2, [.. body]);
    }

    /// <summary>
    /// An application_layer_protocol_negotiation extension. A client offers a list; a
    /// server names one.
    /// </summary>
    private static byte[] AlpnExtension(string protocol, bool asClient)
    {
        var name = System.Text.Encoding.ASCII.GetBytes(protocol);

        var list = new List<byte> { (byte)name.Length };
        list.AddRange(name);

        var payload = new List<byte>();

        if (asClient)
        {
            payload.AddRange(UInt16(list.Count));
        }

        payload.AddRange(list);

        var extension = new List<byte> { 0x00, 0x10 };
        extension.AddRange(UInt16(payload.Count));
        extension.AddRange(payload);

        return [.. extension];
    }

    private static byte[] SupportedVersions(bool asClient)
    {
        // A client sends a list; a server sends the single version it chose.
        var payload = asClient
            ? (byte[])[0x02, 0x03, 0x04]
            : [0x03, 0x04];

        var extension = new List<byte> { 0x00, 0x2b };
        extension.AddRange(UInt16(payload.Length));
        extension.AddRange(payload);

        return [.. extension];
    }

    private static byte[] Handshake(byte type, byte[] body)
    {
        var message = new byte[4 + body.Length];
        message[0] = type;

        // A handshake message's length is 24 bits.
        message[1] = (byte)(body.Length >> 16);
        message[2] = (byte)(body.Length >> 8);
        message[3] = (byte)body.Length;

        body.CopyTo(message, 4);
        return message;
    }

    private static byte[] UInt16(int value)
    {
        var bytes = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(bytes, (ushort)value);
        return bytes;
    }

    /// <summary>An Ethernet frame carrying an IPv4 TCP segment with the given payload.</summary>
    private static byte[] BuildFrame(
        bool fromClient, ReadOnlySpan<byte> payload, uint sequenceNumber, bool syn, bool ack)
    {
        var frame = new byte[14 + 20 + 20 + payload.Length];
        var span = frame.AsSpan();

        BinaryPrimitives.WriteUInt16BigEndian(span[12..], 0x0800);

        var ip = span[14..];
        ip[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(ip[2..], (ushort)(40 + payload.Length));
        BinaryPrimitives.WriteUInt16BigEndian(ip[6..], 0x4000);     // don't fragment
        ip[8] = 64;
        ip[9] = 6;                                                   // TCP

        (fromClient ? ClientAddress : ServerAddress).CopyTo(ip[12..]);
        (fromClient ? ServerAddress : ClientAddress).CopyTo(ip[16..]);

        // tshark verifies the IPv4 header checksum and will mark the packet bad without
        // it, which in turn stops it reassembling the stream.
        BinaryPrimitives.WriteUInt16BigEndian(ip[10..], Checksum(ip[..20]));

        var tcp = ip[20..];
        BinaryPrimitives.WriteUInt16BigEndian(tcp, (ushort)(fromClient ? ClientPort : ServerPort));
        BinaryPrimitives.WriteUInt16BigEndian(tcp[2..], (ushort)(fromClient ? ServerPort : ClientPort));
        BinaryPrimitives.WriteUInt32BigEndian(tcp[4..], sequenceNumber);
        BinaryPrimitives.WriteUInt32BigEndian(tcp[8..], 1);          // acknowledgement
        tcp[12] = 0x50;                                              // 20-byte header

        // SYN=0x02, ACK=0x10, PSH=0x08. A data segment carries PSH and ACK; the opening
        // SYN carries neither.
        tcp[13] = (byte)((syn ? 0x02 : 0x08) | (ack ? 0x10 : 0x00));
        BinaryPrimitives.WriteUInt16BigEndian(tcp[14..], 64240);     // window

        payload.CopyTo(tcp[20..]);

        // Computed last: the checksum covers the payload, and the field must be zero while
        // it is being computed over itself.
        BinaryPrimitives.WriteUInt16BigEndian(
            tcp[16..], TcpChecksum(ip[12..16], ip[16..20], tcp[..(20 + payload.Length)]));

        return frame;
    }

    /// <summary>The one's-complement sum every IP-family checksum is built from.</summary>
    private static ushort Checksum(ReadOnlySpan<byte> data, uint seed = 0)
    {
        var sum = seed;

        for (var i = 0; i + 1 < data.Length; i += 2)
        {
            sum += (uint)((data[i] << 8) | data[i + 1]);
        }

        if (data.Length % 2 != 0)
        {
            sum += (uint)(data[^1] << 8);
        }

        while (sum >> 16 != 0)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        return (ushort)~sum;
    }

    /// <summary>
    /// A TCP checksum, which covers a pseudo-header of the IP addresses, protocol and
    /// length as well as the segment itself.
    /// </summary>
    private static ushort TcpChecksum(
        ReadOnlySpan<byte> source, ReadOnlySpan<byte> destination, ReadOnlySpan<byte> segment)
    {
        uint sum = 0;

        sum += (uint)((source[0] << 8) | source[1]);
        sum += (uint)((source[2] << 8) | source[3]);
        sum += (uint)((destination[0] << 8) | destination[1]);
        sum += (uint)((destination[2] << 8) | destination[3]);
        sum += 6;                                   // protocol
        sum += (uint)segment.Length;

        // Fold the pseudo-header before handing it on as the seed, so the main sum starts
        // from a value that is already within 16 bits.
        while (sum >> 16 != 0)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        return Checksum(segment, sum);
    }
}
