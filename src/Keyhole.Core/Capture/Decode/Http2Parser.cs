using System.Buffers.Binary;

namespace Keyhole.Core.Capture.Decode;

/// <summary>
/// Recovers requests and responses from a decrypted HTTP/2 connection.
///
/// HTTP/2 multiplexes: one connection carries many exchanges at once, interleaved as
/// frames and identified by a stream id. So a request and its response are not adjacent in
/// the byte stream, and pairing them means tracking streams rather than reading
/// sequentially — which is the whole reason a browser capture decoded as HTTP/1.1 would
/// show nothing at all.
///
/// Headers are the other half of the problem: they are HPACK-compressed against a table
/// built from every header block sent so far, so the frames have to be walked in order and
/// none may be skipped.
/// </summary>
public static class Http2Parser
{
    /// <summary>
    /// The 24 bytes a client sends before anything else on an HTTP/2 connection.
    /// Its presence is how a decrypted stream is known to be HTTP/2 rather than HTTP/1.1 —
    /// ALPN says so too, but ALPN is in the encrypted handshake.
    /// </summary>
    private static ReadOnlySpan<byte> ConnectionPreface => "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8;

    public static bool LooksLikeHttp2(ReadOnlySpan<byte> clientStream) =>
        clientStream.Length >= ConnectionPreface.Length &&
        clientStream[..ConnectionPreface.Length].SequenceEqual(ConnectionPreface);

    private const byte FrameData = 0x0;
    private const byte FrameHeaders = 0x1;
    private const byte FramePushPromise = 0x5;
    private const byte FrameContinuation = 0x9;

    private const byte FlagEndStream = 0x1;
    private const byte FlagEndHeaders = 0x4;
    private const byte FlagPadded = 0x8;
    private const byte FlagPriority = 0x20;

    /// <summary>
    /// A frame's length field is 24 bits, but the protocol's own default maximum is 16384
    /// and a peer must announce anything larger. A value far beyond that means the stream
    /// has lost alignment.
    /// </summary>
    private const int MaxFrameLength = 1 << 22;

    /// <summary>
    /// Parses both directions of one connection.
    /// </summary>
    /// <param name="clientStream">Decrypted bytes the client sent.</param>
    /// <param name="serverStream">Decrypted bytes the server sent.</param>
    /// <param name="conversation">How to label the exchanges, for the UI.</param>
    /// <param name="requestedUtc">When the connection's first byte was captured.</param>
    /// <param name="respondedUtc">When its last byte was captured.</param>
    public static IReadOnlyList<DecodedExchange> Parse(
        ReadOnlyMemory<byte> clientStream,
        ReadOnlyMemory<byte> serverStream,
        string conversation,
        DateTimeOffset requestedUtc,
        DateTimeOffset? respondedUtc)
    {
        var streams = new Dictionary<uint, Http2Stream>();

        // One decoder per direction: the dynamic tables are separate, and feeding both
        // directions' blocks into one would corrupt both.
        var requestDecoder = new HpackDecoder();
        var responseDecoder = new HpackDecoder();

        var client = clientStream;
        if (LooksLikeHttp2(client.Span))
        {
            client = client[ConnectionPreface.Length..];
        }

        ReadFrames(client, requestDecoder, streams, isRequest: true);
        ReadFrames(serverStream, responseDecoder, streams, isRequest: false);

        var exchanges = new List<DecodedExchange>();

        // Ascending stream id is the order the client opened them, which is the closest
        // thing HTTP/2 offers to request order.
        foreach (var (id, stream) in streams.OrderBy(s => s.Key))
        {
            if (stream.RequestHeaders.Count == 0)
            {
                // A server push with no matching request, or a stream whose HEADERS frame
                // fell outside the capture. Nothing to show.
                continue;
            }

            exchanges.Add(stream.ToExchange(conversation, id, requestedUtc, respondedUtc));
        }

        return exchanges;
    }

    /// <summary>
    /// Walks one direction's frames, accumulating per-stream state.
    /// </summary>
    private static void ReadFrames(
        ReadOnlyMemory<byte> data,
        HpackDecoder decoder,
        Dictionary<uint, Http2Stream> streams,
        bool isRequest)
    {
        var offset = 0;

        // A header block can be split across a HEADERS frame and any number of
        // CONTINUATION frames, and must be decoded as one block — HPACK's encoding does
        // not survive being cut at a frame boundary.
        var pendingBlock = new MemoryStream();
        uint pendingStream = 0;
        var pendingEndStream = false;
        var collecting = false;

        while (offset + 9 <= data.Length)
        {
            var header = data.Span.Slice(offset, 9);

            var length = (header[0] << 16) | (header[1] << 8) | header[2];
            var type = header[3];
            var flags = header[4];

            // The top bit of the stream id is reserved and must be ignored rather than
            // read as part of the number.
            var streamId = BinaryPrimitives.ReadUInt32BigEndian(header[5..]) & 0x7FFFFFFF;

            if (length > MaxFrameLength || offset + 9 + length > data.Length)
            {
                break;
            }

            var payload = data.Slice(offset + 9, length);
            offset += 9 + length;

            switch (type)
            {
                case FrameHeaders or FramePushPromise:
                {
                    var fragment = StripHeaderPadding(payload.Span, flags, type);

                    pendingBlock.SetLength(0);
                    pendingBlock.Write(fragment);
                    pendingStream = streamId;
                    pendingEndStream = (flags & FlagEndStream) != 0;
                    collecting = (flags & FlagEndHeaders) == 0;

                    if (!collecting)
                    {
                        Apply(streams, decoder, pendingStream, pendingBlock, isRequest, pendingEndStream);
                    }

                    break;
                }

                case FrameContinuation when collecting && streamId == pendingStream:
                {
                    pendingBlock.Write(payload.Span);

                    if ((flags & FlagEndHeaders) != 0)
                    {
                        collecting = false;
                        Apply(streams, decoder, pendingStream, pendingBlock, isRequest, pendingEndStream);
                    }

                    break;
                }

                case FrameData:
                {
                    var body = StripDataPadding(payload.Span, flags);
                    var stream = Get(streams, streamId);

                    // Only the size is kept, not the body. A capture's bodies are the bulk
                    // of its volume, and holding them all in memory to report their
                    // lengths would make decoding a large session impossible.
                    if (isRequest)
                    {
                        stream.RequestBodyBytes += body;
                    }
                    else
                    {
                        stream.ResponseBodyBytes += body;
                    }

                    break;
                }
            }
        }

        if (decoder.IsBroken)
        {
            // HPACK is stateful, so once decoding breaks every later header block on this
            // connection is suspect too -- which is why the flag goes on every stream
            // rather than only on the one that failed.
            foreach (var stream in streams.Values)
            {
                stream.Incomplete ??= Ipc.ReasonCodes.ExchangeHeadersBroken;
            }
        }
    }

    private static void Apply(
        Dictionary<uint, Http2Stream> streams,
        HpackDecoder decoder,
        uint streamId,
        MemoryStream block,
        bool isRequest,
        bool endStream)
    {
        var headers = decoder.Decode(block.GetBuffer().AsSpan(0, (int)block.Length));
        if (headers is null)
        {
            return;
        }

        var stream = Get(streams, streamId);

        if (isRequest)
        {
            // A request can have a second header block: trailers. They follow the body and
            // must not replace the request line.
            if (stream.RequestHeaders.Count == 0)
            {
                stream.RequestHeaders = headers;
            }
        }
        else if (stream.ResponseHeaders.Count == 0)
        {
            stream.ResponseHeaders = headers;
        }

        if (endStream && !isRequest)
        {
            stream.ResponseComplete = true;
        }
    }

    private static Http2Stream Get(Dictionary<uint, Http2Stream> streams, uint id)
    {
        if (!streams.TryGetValue(id, out var stream))
        {
            stream = new Http2Stream();
            streams[id] = stream;
        }

        return stream;
    }

    /// <summary>
    /// Removes a HEADERS frame's optional padding and priority fields, leaving the header
    /// block fragment.
    ///
    /// Both are optional and signalled by flags, and feeding either into HPACK would
    /// corrupt the dynamic table for the rest of the connection — not just the frame.
    /// </summary>
    private static ReadOnlySpan<byte> StripHeaderPadding(
        ReadOnlySpan<byte> payload, byte flags, byte type)
    {
        var padding = 0;

        if ((flags & FlagPadded) != 0)
        {
            if (payload.Length < 1)
            {
                return [];
            }

            padding = payload[0];
            payload = payload[1..];
        }

        if (type == FrameHeaders && (flags & FlagPriority) != 0)
        {
            // Stream dependency and weight: four bytes plus one.
            if (payload.Length < 5)
            {
                return [];
            }

            payload = payload[5..];
        }

        if (type == FramePushPromise)
        {
            // The promised stream id precedes the header block.
            if (payload.Length < 4)
            {
                return [];
            }

            payload = payload[4..];
        }

        return padding >= payload.Length ? [] : payload[..^padding];
    }

    /// <summary>The payload length of a DATA frame, after any padding.</summary>
    private static int StripDataPadding(ReadOnlySpan<byte> payload, byte flags)
    {
        if ((flags & FlagPadded) == 0)
        {
            return payload.Length;
        }

        if (payload.Length < 1)
        {
            return 0;
        }

        var padding = payload[0];
        var body = payload.Length - 1 - padding;

        return body < 0 ? 0 : body;
    }
}

/// <summary>One HTTP/2 stream's accumulated state.</summary>
internal sealed class Http2Stream
{
    public IReadOnlyList<HttpHeader> RequestHeaders { get; set; } = [];

    public IReadOnlyList<HttpHeader> ResponseHeaders { get; set; } = [];

    public long RequestBodyBytes { get; set; }

    public long ResponseBodyBytes { get; set; }

    public bool ResponseComplete { get; set; }

    public string? Incomplete { get; set; }

    public DecodedExchange ToExchange(
        string conversation,
        uint streamId,
        DateTimeOffset requestedUtc,
        DateTimeOffset? respondedUtc)
    {
        var method = Pseudo(RequestHeaders, ":method") ?? "?";
        var scheme = Pseudo(RequestHeaders, ":scheme") ?? "https";
        var authority = Pseudo(RequestHeaders, ":authority")
                        ?? Find(RequestHeaders, "host")
                        ?? "";
        var path = Pseudo(RequestHeaders, ":path") ?? "";

        var status = Pseudo(ResponseHeaders, ":status");

        var incomplete = Incomplete;

        if (incomplete is null && ResponseHeaders.Count == 0)
        {
            incomplete = Ipc.ReasonCodes.ExchangeNoResponse;
        }
        else if (incomplete is null && !ResponseComplete)
        {
            // The response was still arriving when the capture stopped, so its body size
            // is a floor rather than a total.
            incomplete = Ipc.ReasonCodes.ExchangeResponseTruncated;
        }

        return new DecodedExchange
        {
            Conversation = $"{conversation} stream {streamId}",
            Protocol = "HTTP/2",
            Method = method,
            Url = authority.Length > 0 ? $"{scheme}://{authority}{path}" : path,
            StatusCode = int.TryParse(status, out var code) ? code : null,

            // The pseudo-headers are protocol plumbing, not headers a user wants to read;
            // the method, URL and status columns already say what they said.
            RequestHeaders = [.. RequestHeaders.Where(h => !h.Name.StartsWith(':'))],
            ResponseHeaders = [.. ResponseHeaders.Where(h => !h.Name.StartsWith(':'))],

            RequestBodyBytes = RequestBodyBytes,
            ResponseBodyBytes = ResponseBodyBytes,
            RequestedUtc = requestedUtc,
            RespondedUtc = ResponseHeaders.Count > 0 ? respondedUtc : null,
            Incomplete = incomplete,
        };
    }

    private static string? Pseudo(IReadOnlyList<HttpHeader> headers, string name) =>
        headers.FirstOrDefault(h => h.Name == name)?.Value;

    private static string? Find(IReadOnlyList<HttpHeader> headers, string name) =>
        headers.FirstOrDefault(h => h.Name.Equals(name, StringComparison.OrdinalIgnoreCase))?.Value;
}
