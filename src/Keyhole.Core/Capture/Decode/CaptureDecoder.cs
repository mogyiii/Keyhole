using Keyhole.Core.Capture.Pcapng;
using Keyhole.Core.Capture.Recording;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Keyhole.Core.Capture.Decode;

/// <summary>
/// Turns a capture file into the list of requests and responses the application made.
///
/// The whole pipeline, in one place: read the file's packets and its embedded TLS secrets,
/// reassemble each TCP conversation, decrypt it with the secret matching its handshake,
/// then read HTTP out of the plaintext. Every stage can fail for ordinary reasons, and the
/// reasons are carried through rather than collapsed into an empty list — "nothing was
/// decoded" and "nothing was decodable" look identical in a UI unless the difference is
/// reported.
///
/// Works from the file rather than from the live capture, so a session can be decoded
/// again at any time and decoding can never disturb a recording in progress.
/// </summary>
public sealed class CaptureDecoder(ILogger<CaptureDecoder>? logger = null)
{
    private readonly ILogger _logger = logger ?? NullLogger<CaptureDecoder>.Instance;

    /// <summary>
    /// A ceiling on conversations held at once.
    ///
    /// Reassembly keeps both directions of each conversation in memory, so a capture of a
    /// busy browser session could otherwise need more memory than the capture file itself.
    /// The excess is reported rather than silently dropped.
    /// </summary>
    private const int MaxConversations = 4096;

    /// <summary>
    /// Decodes a session's capture.
    /// </summary>
    /// <param name="pcapngPath">The capture file, which carries its own TLS secrets.</param>
    /// <param name="fallbackKeylog">
    /// The session's keylog from disk, used when the capture has no secrets embedded —
    /// which is the case for a capture that is still running, since the secrets are
    /// written in at the end.
    /// </param>
    public DecodeResult Decode(string pcapngPath, string? fallbackKeylog = null)
    {
        if (!File.Exists(pcapngPath))
        {
            return DecodeResult.Failed(
                "This session has no packet capture. Packet recording needs Npcap; the " +
                "TLS keylog was collected either way.");
        }

        try
        {
            return DecodeCore(pcapngPath, fallbackKeylog);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return DecodeResult.Failed($"The capture file could not be read: {ex.Message}");
        }
        catch (Exception ex)
        {
            // Decoding parses hostile-shaped data by nature. A crash here must not take
            // the service down, and the user is better served by a reason than a silence.
            _logger.LogError(ex, "Decoding {Path} failed.", pcapngPath);
            return DecodeResult.Failed($"The capture could not be decoded: {ex.Message}");
        }
    }

    private DecodeResult DecodeCore(string pcapngPath, string? fallbackKeylog)
    {
        var conversations = new Dictionary<ConversationKey, Conversation>();
        var keylogText = new List<string>();
        var quicBytes = 0L;
        var overflowed = false;

        foreach (var record in PcapngReader.Read(pcapngPath))
        {
            if (record.Kind == PcapngRecordKind.Secrets)
            {
                if (record.Keylog is { } embedded)
                {
                    keylogText.Add(embedded);
                }

                continue;
            }

            if (TransportSegment.TryRead(record.Frame, record.LinkType) is not { } segment)
            {
                continue;
            }

            if (segment.Protocol == ProtocolType.Udp)
            {
                // QUIC carries HTTP/3, and Chrome prefers it wherever a server offers it.
                // Keyhole cannot decode it, so it is measured and reported — otherwise a
                // browser capture looks mysteriously empty.
                if (segment.Source.Port == 443 || segment.Destination.Port == 443)
                {
                    quicBytes += segment.Payload.Length;
                }

                continue;
            }

            var key = segment.Conversation;

            if (!conversations.TryGetValue(key, out var conversation))
            {
                if (conversations.Count >= MaxConversations)
                {
                    overflowed = true;
                    continue;
                }

                conversation = new Conversation(key);
                conversations[key] = conversation;
            }

            conversation.Add(segment, record.Timestamp);
        }

        // The capture's own secrets take precedence; the keylog on disk is the fallback for
        // a session still in progress.
        var keylog = TlsKeylog.Parse(
            keylogText.Count > 0 ? string.Join('\n', keylogText) : fallbackKeylog);

        var exchanges = new List<DecodedExchange>();
        var decrypted = 0;
        var withoutKeys = 0;
        var handshakeMissing = 0;
        var failed = 0;

        foreach (var conversation in conversations.Values)
        {
            var result = conversation.Decode(keylog);

            // Every outcome lands in exactly one bucket. An earlier version left two of
            // them uncounted, which meant a real run could report "10 of 16 decrypted"
            // with no account of the other six — and the missing six were the interesting
            // ones.
            switch (result.Decryption.Outcome)
            {
                case TlsDecryptionOutcome.Decrypted:
                    decrypted++;
                    break;

                case TlsDecryptionOutcome.NoKeys:
                case TlsDecryptionOutcome.UnsupportedSuite:
                    withoutKeys++;
                    break;

                case TlsDecryptionOutcome.NoHandshake:
                    handshakeMissing++;
                    break;

                case TlsDecryptionOutcome.Failed:
                    failed++;
                    break;

                case TlsDecryptionOutcome.NotTls:
                    // Not a TLS conversation, so it is not in the TLS totals at all.
                    break;
            }

            exchanges.AddRange(result.Exchanges);
        }

        _logger.LogInformation(
            "Decoded {Path}: {Conversations} conversations, {Decrypted} decrypted, " +
            "{NoKeys} without keys, {NoHandshake} missing a handshake, {Failed} failed, " +
            "{Exchanges} exchanges, {Quic} QUIC bytes.",
            pcapngPath, conversations.Count, decrypted, withoutKeys, handshakeMissing,
            failed, exchanges.Count, quicBytes);

        return new DecodeResult
        {
            Exchanges = [.. exchanges.OrderBy(e => e.RequestedUtc)],

            // Only TLS conversations are counted: a capture also picks up the target's
            // plain DNS-over-TCP or other traffic, and counting those as undecrypted TLS
            // would make the summary read worse than the truth.
            Conversations = conversations.Values.Count(c => c.IsTls),
            Decrypted = decrypted,
            EncryptedWithoutKeys = withoutKeys,
            HandshakeMissing = handshakeMissing,
            DecryptionFailed = failed,
            QuicBytes = quicBytes,
            Failure = overflowed
                ? $"The capture holds more than {MaxConversations} connections; only the " +
                  "first were decoded."
                : null,
        };
    }
}

/// <summary>
/// One TCP conversation being reassembled, with a direction each way.
///
/// Which side is the client is decided by the SYN, falling back to the first sender seen.
/// It matters: the two directions use different keys, and swapping them decrypts nothing.
/// </summary>
internal sealed class Conversation(ConversationKey key)
{
    private readonly TcpStream _client = new();
    private readonly TcpStream _server = new();

    /// <summary>
    /// The endpoint identified as the client, as "address:port". Null until the first
    /// segment establishes it.
    /// </summary>
    private string? _clientEndpoint;

    /// <summary>Set once something in this conversation looked like a TLS record.</summary>
    public bool IsTls { get; private set; }

    public void Add(TransportSegment segment, DateTimeOffset timestamp)
    {
        var source = segment.Source.ToString();

        // A SYN without an ACK is sent only by the side opening the connection, which
        // settles the direction definitively. Without one — a capture that began
        // mid-connection — the first sender seen is assumed to be the client, which is
        // right whenever the capture caught the request.
        //
        // Checking the ACK flag is what makes this work: the server's reply is a SYN too,
        // and treating any SYN as the opener hands the client's role to whichever side
        // sent one last.
        _clientEndpoint ??= source;

        if (segment.IsConnectionOpener)
        {
            _clientEndpoint = source;
        }

        var stream = source == _clientEndpoint ? _client : _server;
        stream.Add(segment.SequenceNumber, segment.Payload, segment.IsSyn, timestamp);
    }

    public ConversationResult Decode(TlsKeylog keylog)
    {
        var clientBytes = _client.Bytes;
        var serverBytes = _server.Bytes;

        var label = key.ToString();

        var requestedUtc = _client.FirstSeenUtc ?? _server.FirstSeenUtc ?? DateTimeOffset.UnixEpoch;
        var respondedUtc = _server.LastSeenUtc;

        var decryption = TlsConversation.Decrypt(clientBytes, serverBytes, keylog);
        IsTls = decryption.IsTls;

        if (!decryption.IsDecrypted)
        {
            // Not decryptable, but it may not be TLS at all — plain HTTP on a non-standard
            // port is worth reading rather than discarding.
            if (!decryption.IsTls)
            {
                return new ConversationResult(
                    decryption,
                    ReadHttp(clientBytes, serverBytes, label, requestedUtc, respondedUtc));
            }

            return new ConversationResult(decryption, []);
        }

        return new ConversationResult(
            decryption,
            ReadHttp(
                decryption.ClientPlaintext,
                decryption.ServerPlaintext,
                label,
                requestedUtc,
                respondedUtc));
    }

    /// <summary>
    /// Reads HTTP from plaintext, choosing the version by what the client actually sent.
    ///
    /// The connection preface settles HTTP/2 beyond doubt, and a request line settles
    /// HTTP/1.1. Anything else — a WebSocket after its upgrade, gRPC's framing, a protocol
    /// Keyhole does not know — yields nothing, which is the honest answer.
    /// </summary>
    private static IReadOnlyList<DecodedExchange> ReadHttp(
        ReadOnlyMemory<byte> client,
        ReadOnlyMemory<byte> server,
        string label,
        DateTimeOffset requestedUtc,
        DateTimeOffset? respondedUtc)
    {
        if (Http2Parser.LooksLikeHttp2(client.Span))
        {
            return Http2Parser.Parse(client, server, label, requestedUtc, respondedUtc);
        }

        if (Http1Parser.LooksLikeHttp1(client.Span))
        {
            return Http1Parser.Parse(client, server, label, requestedUtc, respondedUtc);
        }

        return [];
    }
}

internal sealed record ConversationResult(
    TlsDecryption Decryption,
    IReadOnlyList<DecodedExchange> Exchanges);
