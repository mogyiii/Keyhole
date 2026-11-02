using System.Buffers.Binary;
using System.Diagnostics;
using Keyhole.Core.Capture.Decode;
using Keyhole.Core.Ipc;

namespace Keyhole.Tests;

/// <summary>
/// HTTP/2 over TLS 1.3, which is what a browser capture almost entirely consists of.
///
/// Worth its own tests because nothing about HTTP/1.1 exercises it: HTTP/2 multiplexes, so
/// requests and responses are not adjacent in the stream and have to be matched by stream
/// id, and its headers are HPACK-compressed rather than text. A decoder that handles
/// HTTP/1.1 perfectly shows an empty list for a real browser session.
/// </summary>
public class Http2SessionTests
{
    [Fact]
    public void A_request_and_response_are_paired_by_stream()
    {
        var (path, _) = Http2Session.Write();

        try
        {
            var result = new CaptureDecoder().Decode(path);

            Assert.Null(result.Failure);
            Assert.Equal(1, result.Decrypted);

            var exchange = Assert.Single(result.Exchanges);

            Assert.Equal("HTTP/2", exchange.Protocol);
            Assert.Equal("GET", exchange.Method);
            Assert.Equal("https://example.com/api/items?page=2", exchange.Url);
            Assert.Equal(200, exchange.StatusCode);

            // The body arrived in DATA frames, which is where HTTP/2 puts it; a parser
            // that only read headers would report zero.
            Assert.Equal(11, exchange.ResponseBodyBytes);

            Assert.Contains(
                exchange.RequestHeaders,
                h => h.Name == "user-agent" && h.Value == "Keyhole-Test/1.0");

            Assert.Equal("application/json", exchange.ContentType);

            // The pseudo-headers carry the method, path, scheme and status, which the
            // columns already show. Repeating them in the header list would be noise.
            Assert.DoesNotContain(exchange.RequestHeaders, h => h.Name.StartsWith(':'));
            Assert.DoesNotContain(exchange.ResponseHeaders, h => h.Name.StartsWith(':'));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Several_interleaved_streams_all_come_back()
    {
        // The property that distinguishes HTTP/2 from HTTP/1.1: three requests in flight
        // at once, their responses returning out of order. Pairing by position — which is
        // right for HTTP/1.1 — would mismatch every one of them.
        var (path, _) = Http2Session.WriteInterleaved();

        try
        {
            var result = new CaptureDecoder().Decode(path);
            var exchanges = result.Exchanges;

            Assert.Equal(3, exchanges.Count);

            Assert.Collection(
                exchanges,
                e =>
                {
                    Assert.Equal("https://example.com/first", e.Url);
                    Assert.Equal(200, e.StatusCode);
                },
                e =>
                {
                    Assert.Equal("https://example.com/second", e.Url);
                    Assert.Equal(404, e.StatusCode);
                },
                e =>
                {
                    Assert.Equal("https://example.com/third", e.Url);
                    Assert.Equal(500, e.StatusCode);
                });
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void A_request_with_no_response_is_reported_as_incomplete()
    {
        // Normal at the end of a capture: the session stopped while a request was in
        // flight. Showing it with a blank status and no explanation would read as a
        // decoding failure.
        var (path, _) = Http2Session.WriteRequestOnly();

        try
        {
            var exchange = Assert.Single(new CaptureDecoder().Decode(path).Exchanges);

            Assert.Null(exchange.StatusCode);
            Assert.Null(exchange.Duration);
            Assert.NotNull(exchange.Incomplete);
            Assert.Equal(ReasonCodes.ExchangeNoResponse, exchange.Incomplete);
        }
        finally
        {
            File.Delete(path);
        }
    }

    /// <summary>
    /// Wireshark reading the same HTTP/2 capture, which independently checks the HPACK
    /// decoding as well as the TLS: it builds its own dynamic table from the same frames.
    /// </summary>
    [WiresharkFact]
    public void Tshark_reads_the_same_http2_request()
    {
        var tshark = PcapngWiresharkTests.WiresharkTool("tshark.exe")!;
        var (path, _) = Http2Session.Write();

        try
        {
            var output = PcapngWiresharkTests.Run(
                tshark,
                $"-r \"{path}\" -d tcp.port==443,tls -T fields " +
                "-e http2.headers.method -e http2.headers.path -e http2.headers.status");

            Assert.Contains("GET", output);
            Assert.Contains("/api/items?page=2", output);
            Assert.Contains("200", output);
        }
        finally
        {
            File.Delete(path);
        }
    }
}

/// <summary>
/// Builds HTTP/2 byte streams and wraps them in a TLS 1.3 capture.
///
/// Headers are HPACK-encoded as literals without indexing, which is the simplest form the
/// RFC allows and keeps the test's own encoder honest — a test that leaned on the dynamic
/// table would be exercising its own understanding of HPACK twice over rather than
/// Keyhole's once.
/// </summary>
internal static class Http2Session
{
    private static ReadOnlySpan<byte> Preface => "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8;

    public static (string Path, string Keylog) Write()
    {
        var client = new MemoryStream();
        client.Write(Preface);
        client.Write(Settings());
        client.Write(Headers(1, endStream: true,
        [
            (":method", "GET"),
            (":scheme", "https"),
            (":authority", "example.com"),
            (":path", "/api/items?page=2"),
            ("user-agent", "Keyhole-Test/1.0"),
            ("accept", "application/json"),
        ]));

        var server = new MemoryStream();
        server.Write(Settings());
        server.Write(Headers(1, endStream: false,
        [
            (":status", "200"),
            ("content-type", "application/json"),
            ("content-length", "11"),
        ]));
        server.Write(Data(1, "{\"items\":1}"u8.ToArray(), endStream: true));

        return TlsSessionBuilder.WriteCapture(
            client.ToArray(), server.ToArray(), embedSecrets: true, alpn: "h2");
    }

    public static (string Path, string Keylog) WriteInterleaved()
    {
        var client = new MemoryStream();
        client.Write(Preface);
        client.Write(Settings());

        // All three requests go out before any response comes back, which is the point.
        foreach (var (id, path) in (( uint, string )[])[(1, "/first"), (3, "/second"), (5, "/third")])
        {
            client.Write(Headers(id, endStream: true,
            [
                (":method", "GET"),
                (":scheme", "https"),
                (":authority", "example.com"),
                (":path", path),
            ]));
        }

        var server = new MemoryStream();
        server.Write(Settings());

        // Responses in a different order from the requests, and with different statuses,
        // so a positional pairing produces visibly wrong answers rather than plausible
        // ones.
        server.Write(Headers(5, endStream: true, [(":status", "500")]));
        server.Write(Headers(1, endStream: true, [(":status", "200")]));
        server.Write(Headers(3, endStream: true, [(":status", "404")]));

        return TlsSessionBuilder.WriteCapture(
            client.ToArray(), server.ToArray(), embedSecrets: true, alpn: "h2");
    }

    public static (string Path, string Keylog) WriteRequestOnly()
    {
        var client = new MemoryStream();
        client.Write(Preface);
        client.Write(Settings());
        client.Write(Headers(1, endStream: true,
        [
            (":method", "POST"),
            (":scheme", "https"),
            (":authority", "example.com"),
            (":path", "/submit"),
        ]));

        var server = new MemoryStream();
        server.Write(Settings());

        return TlsSessionBuilder.WriteCapture(
            client.ToArray(), server.ToArray(), embedSecrets: true, alpn: "h2");
    }

    /// <summary>An empty SETTINGS frame, which both ends must send first.</summary>
    private static byte[] Settings() => Frame(type: 0x4, flags: 0, streamId: 0, []);

    private static byte[] Headers(
        uint streamId, bool endStream, (string Name, string Value)[] headers)
    {
        var block = new MemoryStream();

        foreach (var (name, value) in headers)
        {
            // Literal Header Field without Indexing, new name: 0000 0000, then two
            // length-prefixed strings with the Huffman bit clear.
            block.WriteByte(0x00);
            WriteString(block, name);
            WriteString(block, value);
        }

        // END_HEADERS is always set: the block is never split here, so there is no
        // CONTINUATION frame.
        var flags = (byte)(0x4 | (endStream ? 0x1 : 0x0));

        return Frame(0x1, flags, streamId, block.ToArray());
    }

    private static byte[] Data(uint streamId, byte[] body, bool endStream) =>
        Frame(0x0, endStream ? (byte)0x1 : (byte)0x0, streamId, body);

    private static void WriteString(Stream stream, string value)
    {
        var bytes = System.Text.Encoding.ASCII.GetBytes(value);

        // Lengths below 127 fit in the prefix, which every header in these tests does.
        if (bytes.Length >= 127)
        {
            throw new ArgumentException("Test headers are short by design.", nameof(value));
        }

        stream.WriteByte((byte)bytes.Length);
        stream.Write(bytes);
    }

    private static byte[] Frame(byte type, byte flags, uint streamId, byte[] payload)
    {
        var frame = new byte[9 + payload.Length];

        // The length is 24 bits, big-endian.
        frame[0] = (byte)(payload.Length >> 16);
        frame[1] = (byte)(payload.Length >> 8);
        frame[2] = (byte)payload.Length;
        frame[3] = type;
        frame[4] = flags;

        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(5), streamId);
        payload.CopyTo(frame, 9);

        return frame;
    }
}
