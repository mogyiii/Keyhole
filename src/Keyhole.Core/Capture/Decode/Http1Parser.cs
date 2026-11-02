using System.Text;

namespace Keyhole.Core.Capture.Decode;

/// <summary>
/// Recovers requests and responses from a decrypted HTTP/1.1 connection.
///
/// Simpler than HTTP/2 in that one connection carries one exchange at a time, so requests
/// and responses pair up by position. The work is in the bodies: finding where a message
/// ends is the only way to find where the next one starts, and HTTP/1.1 offers three
/// different ways of saying how long a body is. Getting that wrong does not corrupt one
/// message, it loses every message after it.
/// </summary>
public static class Http1Parser
{
    private static ReadOnlySpan<byte> HeaderTerminator => "\r\n\r\n"u8;

    /// <summary>The methods a request line may plausibly start with.</summary>
    private static readonly string[] Methods =
    [
        "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT",
    ];

    public static bool LooksLikeHttp1(ReadOnlySpan<byte> clientStream)
    {
        if (clientStream.Length < 4)
        {
            return false;
        }

        var start = Encoding.ASCII.GetString(clientStream[..Math.Min(8, clientStream.Length)]);

        return Methods.Any(m => start.StartsWith(m, StringComparison.Ordinal));
    }

    /// <summary>
    /// Parses both directions of one connection, pairing each request with the response at
    /// the same position.
    /// </summary>
    public static IReadOnlyList<DecodedExchange> Parse(
        ReadOnlyMemory<byte> clientStream,
        ReadOnlyMemory<byte> serverStream,
        string conversation,
        DateTimeOffset requestedUtc,
        DateTimeOffset? respondedUtc)
    {
        var requests = ReadMessages(clientStream, isResponse: false);
        var responses = ReadMessages(serverStream, isResponse: true);

        var exchanges = new List<DecodedExchange>();

        for (var i = 0; i < requests.Count; i++)
        {
            var request = requests[i];

            // Pipelining is rare but legal, and responses come back in request order, so
            // position is the pairing. A missing response simply means the capture ended
            // before it arrived.
            var response = i < responses.Count ? responses[i] : null;

            var host = request.Headers
                .FirstOrDefault(h => h.Name.Equals("host", StringComparison.OrdinalIgnoreCase))
                ?.Value;

            exchanges.Add(new DecodedExchange
            {
                Conversation = conversation,
                Protocol = request.Version,
                Method = request.Method,
                Url = BuildUrl(request, host),
                StatusCode = response?.StatusCode,
                RequestHeaders = request.Headers,
                ResponseHeaders = response?.Headers ?? [],
                RequestBodyBytes = request.BodyBytes,
                ResponseBodyBytes = response?.BodyBytes ?? 0,
                RequestedUtc = requestedUtc,
                RespondedUtc = response is null ? null : respondedUtc,
                Incomplete = response is null
                    ? Ipc.ReasonCodes.ExchangeNoResponse
                    : response.Incomplete,
            });
        }

        return exchanges;
    }

    /// <summary>
    /// Builds a displayable URL from a request line and its Host header.
    ///
    /// HTTP/1.1 has four shapes of request target and only one of them is a path. Treating
    /// them all as paths and gluing the Host header in front produced
    /// <c>https://www.google.com:443www.google.com:443</c> in a real capture — a CONNECT
    /// request, whose target is an authority and already says everything.
    /// </summary>
    private static string BuildUrl(Http1Message request, string? host)
    {
        var target = request.Target;

        // Absolute form: a proxy request carries the whole URL already.
        if (target.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
            target.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            return target;
        }

        // Authority form: CONNECT, used to open a tunnel. The target is "host:port" and
        // there is no path, so there is nothing to append it to.
        if (request.Method.Equals("CONNECT", StringComparison.OrdinalIgnoreCase))
        {
            return target;
        }

        // Asterisk form: OPTIONS * applies to the server rather than to any resource.
        if (target == "*")
        {
            return host is { Length: > 0 } ? $"{host} (server-wide OPTIONS)" : target;
        }

        // Origin form, which is everything else: a path, with the authority in the Host
        // header. The scheme is assumed https because this stream was decrypted out of a
        // TLS connection to get here.
        if (host is { Length: > 0 } && target.StartsWith('/'))
        {
            return $"https://{host}{target}";
        }

        return target;
    }

    /// <summary>
    /// Walks a direction's stream, yielding one message per request or response.
    ///
    /// Stops at the first message whose headers do not parse: the stream's framing is then
    /// unknown, and guessing where the next message begins would invent messages.
    /// </summary>
    private static List<Http1Message> ReadMessages(ReadOnlyMemory<byte> stream, bool isResponse)
    {
        var messages = new List<Http1Message>();
        var offset = 0;

        while (offset < stream.Length)
        {
            var remaining = stream.Span[offset..];
            var headerEnd = remaining.IndexOf(HeaderTerminator);

            if (headerEnd < 0)
            {
                break;
            }

            var headerText = Encoding.Latin1.GetString(remaining[..headerEnd]);
            offset += headerEnd + HeaderTerminator.Length;

            var message = ParseHead(headerText, isResponse);
            if (message is null)
            {
                break;
            }

            var bodyStart = offset;
            offset = SkipBody(stream, offset, message, isResponse);
            message.BodyBytes = offset - bodyStart;

            messages.Add(message);

            // A body whose length cannot be determined runs to the end of the connection,
            // so there is nothing after it to read.
            if (offset >= stream.Length)
            {
                break;
            }
        }

        return messages;
    }

    private static Http1Message? ParseHead(string headerText, bool isResponse)
    {
        var lines = headerText.Split("\r\n");
        if (lines.Length == 0)
        {
            return null;
        }

        var message = new Http1Message();
        var startLine = lines[0].Split(' ', 3);

        if (isResponse)
        {
            // HTTP/1.1 200 OK
            if (startLine.Length < 2 || !startLine[0].StartsWith("HTTP/", StringComparison.Ordinal))
            {
                return null;
            }

            message.Version = startLine[0];

            if (!int.TryParse(startLine[1], out var status))
            {
                return null;
            }

            message.StatusCode = status;
        }
        else
        {
            // GET /path HTTP/1.1
            if (startLine.Length < 3 || !startLine[2].StartsWith("HTTP/", StringComparison.Ordinal))
            {
                return null;
            }

            message.Method = startLine[0];
            message.Target = startLine[1];
            message.Version = startLine[2];
        }

        var headers = new List<HttpHeader>();

        foreach (var line in lines.Skip(1))
        {
            if (line.Length == 0)
            {
                continue;
            }

            var colon = line.IndexOf(':');
            if (colon <= 0)
            {
                continue;
            }

            headers.Add(new HttpHeader(line[..colon], line[(colon + 1)..].TrimStart()));
        }

        message.Headers = headers;
        return message;
    }

    /// <summary>
    /// Advances past a message's body and returns where the next message starts.
    ///
    /// The three framings HTTP/1.1 defines, in the precedence the RFC gives them: chunked
    /// wins over Content-Length, and with neither, a response body runs to the end of the
    /// connection while a request simply has none.
    /// </summary>
    private static int SkipBody(
        ReadOnlyMemory<byte> stream, int offset, Http1Message message, bool isResponse)
    {
        if (message.IsChunked)
        {
            return SkipChunked(stream, offset, message);
        }

        if (message.ContentLength is { } length)
        {
            var end = offset + length;

            if (end > stream.Length)
            {
                // The body was still arriving when the capture stopped.
                message.Incomplete = Ipc.ReasonCodes.ExchangeBodyTruncated;
                return (int)stream.Length;
            }

            return (int)end;
        }

        // A 204 or 304, or a response to HEAD, has no body regardless of what follows.
        if (isResponse && message.StatusCode is 204 or 304)
        {
            return offset;
        }

        if (!isResponse)
        {
            // A request with no length and no chunking has no body.
            return offset;
        }

        // Connection-delimited: everything left belongs to this response.
        return (int)stream.Length;
    }

    private static int SkipChunked(ReadOnlyMemory<byte> stream, int offset, Http1Message message)
    {
        while (offset < stream.Length)
        {
            var remaining = stream.Span[offset..];
            var lineEnd = remaining.IndexOf("\r\n"u8);

            if (lineEnd < 0)
            {
                message.Incomplete = Ipc.ReasonCodes.ExchangeBodyTruncated;
                return (int)stream.Length;
            }

            var sizeLine = Encoding.ASCII.GetString(remaining[..lineEnd]);

            // A chunk size may carry extensions after a semicolon, and is hexadecimal.
            var semicolon = sizeLine.IndexOf(';');
            var sizeText = (semicolon >= 0 ? sizeLine[..semicolon] : sizeLine).Trim();

            if (!int.TryParse(
                    sizeText,
                    System.Globalization.NumberStyles.HexNumber,
                    System.Globalization.CultureInfo.InvariantCulture,
                    out var chunkSize))
            {
                message.Incomplete = Ipc.ReasonCodes.ExchangeBodyTruncated;
                return (int)stream.Length;
            }

            offset += lineEnd + 2;

            if (chunkSize == 0)
            {
                // The final chunk, then any trailers, then a blank line.
                var tail = stream.Span[offset..];
                var terminator = tail.IndexOf(HeaderTerminator);

                return terminator >= 0
                    ? offset + terminator + HeaderTerminator.Length
                    : Math.Min((int)stream.Length, offset + (tail.IndexOf("\r\n"u8) is var crlf and >= 0 ? crlf + 2 : 0));
            }

            // The chunk, then the CRLF that follows it.
            offset += chunkSize + 2;
        }

        return (int)stream.Length;
    }
}

internal sealed class Http1Message
{
    public string Method { get; set; } = "";

    public string Target { get; set; } = "";

    public string Version { get; set; } = "HTTP/1.1";

    public int? StatusCode { get; set; }

    public IReadOnlyList<HttpHeader> Headers { get; set; } = [];

    public long BodyBytes { get; set; }

    public string? Incomplete { get; set; }

    public bool IsChunked => Headers.Any(h =>
        h.Name.Equals("transfer-encoding", StringComparison.OrdinalIgnoreCase) &&
        h.Value.Contains("chunked", StringComparison.OrdinalIgnoreCase));

    public long? ContentLength =>
        Headers.FirstOrDefault(h =>
            h.Name.Equals("content-length", StringComparison.OrdinalIgnoreCase)) is { } header &&
        long.TryParse(header.Value, out var length) && length >= 0
            ? length
            : null;
}
