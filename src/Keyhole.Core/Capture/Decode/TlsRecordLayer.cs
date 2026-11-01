using System.Buffers.Binary;

namespace Keyhole.Core.Capture.Decode;

/// <summary>
/// Splits a reassembled TCP stream into TLS records, and reads the two handshake messages
/// that say how to decrypt the rest.
///
/// Records are the unit everything else works in: a record is what gets decrypted, and
/// records are counted to produce nonces. They do not align with TCP segments at all — one
/// record routinely spans several segments and one segment carries several records — which
/// is exactly why reassembly has to happen first.
/// </summary>
public static class TlsRecordLayer
{
    public const byte ContentTypeChangeCipherSpec = 20;
    public const byte ContentTypeAlert = 21;
    public const byte ContentTypeHandshake = 22;
    public const byte ContentTypeApplicationData = 23;

    public const byte HandshakeClientHello = 1;
    public const byte HandshakeServerHello = 2;

    /// <summary>
    /// A record's length field is 16 bits but the protocol caps it well below that. A
    /// larger value means this is not TLS, and reading on would consume the stream.
    /// </summary>
    private const int MaxRecordLength = 16384 + 2048;

    /// <summary>
    /// Walks the records in a stream.
    ///
    /// Stops at the first thing that does not look like a record rather than trying to
    /// resynchronise: a stream that has lost alignment cannot be recovered, because record
    /// boundaries are only knowable by having read every preceding one.
    /// </summary>
    public static IEnumerable<TlsRecord> Read(ReadOnlyMemory<byte> stream)
    {
        var offset = 0;

        while (offset + 5 <= stream.Length)
        {
            var header = stream.Span.Slice(offset, 5);
            var contentType = header[0];
            var version = BinaryPrimitives.ReadUInt16BigEndian(header[1..]);
            var length = BinaryPrimitives.ReadUInt16BigEndian(header[3..]);

            if (!IsPlausible(contentType, version) || length == 0 || length > MaxRecordLength)
            {
                yield break;
            }

            if (offset + 5 + length > stream.Length)
            {
                // The record is still arriving, or the capture ended mid-record. Either
                // way there is nothing more to read.
                yield break;
            }

            yield return new TlsRecord(
                contentType,
                version,
                stream.Slice(offset, 5),
                stream.Slice(offset + 5, length));

            offset += 5 + length;
        }
    }

    /// <summary>
    /// Whether a header could begin a TLS record.
    ///
    /// Cheap, and it is what keeps the decoder from reporting plain HTTP or an unrelated
    /// protocol on port 443 as a stream of absurd records.
    /// </summary>
    private static bool IsPlausible(byte contentType, ushort version) =>
        contentType is >= ContentTypeChangeCipherSpec and <= ContentTypeApplicationData &&
        // TLS 1.0 through 1.3. A 1.3 record carries 0x0303 on the wire for compatibility,
        // so the real version is never above that here.
        version is >= 0x0301 and <= 0x0304;

    /// <summary>
    /// Reads the client random out of a ClientHello.
    ///
    /// This is the value that joins a connection in the capture to its line in the keylog,
    /// so without it a connection cannot be decrypted no matter what secrets are present.
    /// </summary>
    public static byte[]? ReadClientRandom(TlsRecord record)
    {
        if (record.ContentType != ContentTypeHandshake)
        {
            return null;
        }

        var body = record.Payload.Span;

        // Handshake header: type, then a 24-bit length.
        if (body.Length < 4 + 2 + 32 || body[0] != HandshakeClientHello)
        {
            return null;
        }

        // Skip the handshake header and the two-byte legacy version; the random follows.
        return body.Slice(4 + 2, 32).ToArray();
    }

    /// <summary>
    /// Reads what a ServerHello settles: the cipher suite, the server random, and the
    /// negotiated version.
    ///
    /// All three are needed. The suite fixes the key derivation, the random is half of
    /// TLS 1.2's key input, and the version decides which of the two key schedules to use
    /// at all — and in TLS 1.3 the version in the header lies, so it has to be read from
    /// the supported_versions extension instead.
    /// </summary>
    public static ServerHello? ReadServerHello(TlsRecord record)
    {
        if (record.ContentType != ContentTypeHandshake)
        {
            return null;
        }

        var body = record.Payload.Span;

        if (body.Length < 4 || body[0] != HandshakeServerHello)
        {
            return null;
        }

        var offset = 4;

        // legacy_version
        if (offset + 2 > body.Length)
        {
            return null;
        }

        var legacyVersion = BinaryPrimitives.ReadUInt16BigEndian(body[offset..]);
        offset += 2;

        if (offset + 32 > body.Length)
        {
            return null;
        }

        var serverRandom = body.Slice(offset, 32).ToArray();
        offset += 32;

        // legacy_session_id_echo, one length byte then that many bytes.
        if (offset >= body.Length)
        {
            return null;
        }

        offset += 1 + body[offset];

        if (offset + 2 > body.Length)
        {
            return null;
        }

        var cipherSuite = BinaryPrimitives.ReadUInt16BigEndian(body[offset..]);
        offset += 2;

        // legacy_compression_method
        offset += 1;

        var version = legacyVersion;

        // In TLS 1.3 the record and legacy version fields both say 1.2, and the real
        // version is in an extension. Reading the legacy field alone would send every 1.3
        // connection down the 1.2 key schedule, which decrypts nothing.
        if (offset + 2 <= body.Length)
        {
            var extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(body[offset..]);
            offset += 2;

            var end = Math.Min(body.Length, offset + extensionsLength);

            while (offset + 4 <= end)
            {
                var extensionType = BinaryPrimitives.ReadUInt16BigEndian(body[offset..]);
                var extensionLength = BinaryPrimitives.ReadUInt16BigEndian(body[(offset + 2)..]);
                offset += 4;

                if (offset + extensionLength > end)
                {
                    break;
                }

                // supported_versions: in a ServerHello it holds the single chosen version.
                if (extensionType == 43 && extensionLength >= 2)
                {
                    version = BinaryPrimitives.ReadUInt16BigEndian(body[offset..]);
                }

                offset += extensionLength;
            }
        }

        return new ServerHello(cipherSuite, serverRandom, version);
    }
}

/// <summary>One TLS record.</summary>
/// <param name="ContentType">
/// What the record carries. In TLS 1.3 an encrypted record always claims
/// application_data regardless of what is inside, and the real type is revealed only after
/// decryption.
/// </param>
/// <param name="Version">The version in the header, which TLS 1.3 deliberately misstates.</param>
/// <param name="Header">
/// The five header bytes, kept because they are the associated data the AEAD
/// authenticates — reconstructing them instead of keeping them is a reliable way to get
/// decryption subtly wrong.
/// </param>
/// <param name="Payload">The record body: ciphertext and tag, for an encrypted record.</param>
public readonly record struct TlsRecord(
    byte ContentType,
    ushort Version,
    ReadOnlyMemory<byte> Header,
    ReadOnlyMemory<byte> Payload);

/// <summary>What the server chose, read from its ServerHello.</summary>
/// <param name="CipherSuite">The suite number, which fixes the whole key schedule.</param>
/// <param name="ServerRandom">Needed by TLS 1.2's derivation; unused in 1.3.</param>
/// <param name="Version">0x0304 for TLS 1.3, 0x0303 for 1.2.</param>
public sealed record ServerHello(ushort CipherSuite, byte[] ServerRandom, ushort Version)
{
    public bool IsTls13 => Version == 0x0304;
}
