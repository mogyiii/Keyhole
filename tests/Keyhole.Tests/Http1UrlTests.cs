using Keyhole.Core.Capture.Decode;

namespace Keyhole.Tests;

/// <summary>
/// How a request line becomes a URL the user can read.
///
/// HTTP/1.1 defines four shapes of request target and only one of them is a path. The
/// first real browser capture decoded a CONNECT as
/// <c>https://www.google.com:443www.google.com:443</c> — the Host header glued in front of
/// a target that was already an authority.
/// </summary>
public class Http1UrlTests
{
    [Theory]
    // Origin form: a path plus the Host header. The common case.
    [InlineData("GET", "/search?q=x", "example.com", "https://example.com/search?q=x")]
    [InlineData("POST", "/submit", "example.com", "https://example.com/submit")]
    // Authority form: CONNECT opens a tunnel and its target is "host:port". There is no
    // path to append, and appending one produced the duplicated string above.
    [InlineData("CONNECT", "www.google.com:443", "www.google.com:443", "www.google.com:443")]
    [InlineData("CONNECT", "example.com:443", "example.com:443", "example.com:443")]
    // Absolute form: a proxy request already carries the whole URL.
    [InlineData("GET", "http://example.com/a", "example.com", "http://example.com/a")]
    [InlineData("GET", "https://example.com/a", "other.com", "https://example.com/a")]
    public void A_request_line_becomes_the_right_url(
        string method, string target, string host, string expected)
    {
        var exchange = Decode(method, target, host);

        Assert.Equal(expected, exchange.Url);
    }

    [Fact]
    public void An_options_asterisk_names_the_server_rather_than_a_resource()
    {
        // OPTIONS * applies to the server itself. "https://example.com*" would be a URL
        // that means nothing.
        var exchange = Decode("OPTIONS", "*", "example.com");

        Assert.DoesNotContain("example.com*", exchange.Url);
        Assert.Contains("example.com", exchange.Url);
    }

    [Fact]
    public void A_request_with_no_host_header_shows_its_target()
    {
        // HTTP/1.0 clients may omit Host. Inventing an authority would be worse than
        // showing the path alone.
        var exchange = Decode("GET", "/health", host: null);

        Assert.Equal("/health", exchange.Url);
    }

    private static DecodedExchange Decode(string method, string target, string? host)
    {
        var request = host is null
            ? $"{method} {target} HTTP/1.1\r\n\r\n"
            : $"{method} {target} HTTP/1.1\r\nHost: {host}\r\n\r\n";

        const string response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";

        var exchanges = Http1Parser.Parse(
            System.Text.Encoding.ASCII.GetBytes(request),
            System.Text.Encoding.ASCII.GetBytes(response),
            "10.0.0.5:51000 <-> 93.184.216.34:443",
            DateTimeOffset.UnixEpoch,
            DateTimeOffset.UnixEpoch);

        return Assert.Single(exchanges);
    }
}
