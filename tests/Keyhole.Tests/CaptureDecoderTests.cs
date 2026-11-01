using System.Diagnostics;
using Keyhole.Core.Capture.Decode;

namespace Keyhole.Tests;

/// <summary>
/// The decode pipeline end to end: a capture file in, requests and responses out.
/// </summary>
public class CaptureDecoderTests
{
    private const string Request =
        "GET /search?q=keyhole HTTP/1.1\r\n" +
        "Host: example.com\r\n" +
        "User-Agent: Keyhole-Test/1.0\r\n" +
        "Accept: text/html\r\n" +
        "\r\n";

    private const string Response =
        "HTTP/1.1 200 OK\r\n" +
        "Content-Type: text/html; charset=utf-8\r\n" +
        "Content-Length: 13\r\n" +
        "Server: synthetic\r\n" +
        "\r\n" +
        "Hello, world!";

    [Fact]
    public void A_tls_session_decodes_into_its_request_and_response()
    {
        var (path, _) = TlsSessionBuilder.WriteCapture(Request, Response);

        try
        {
            var result = new CaptureDecoder().Decode(path);

            Assert.Null(result.Failure);
            Assert.Equal(1, result.Conversations);
            Assert.Equal(1, result.Decrypted);

            var exchange = Assert.Single(result.Exchanges);

            Assert.Equal("GET", exchange.Method);
            Assert.Equal("https://example.com/search?q=keyhole", exchange.Url);
            Assert.Equal(200, exchange.StatusCode);
            Assert.Equal("HTTP/1.1", exchange.Protocol);
            Assert.Equal(13, exchange.ResponseBodyBytes);
            Assert.Equal("text/html; charset=utf-8", exchange.ContentType);

            Assert.Contains(
                exchange.RequestHeaders,
                h => h.Name == "User-Agent" && h.Value == "Keyhole-Test/1.0");

            // Timing comes from the capture's own timestamps, so it covers network time
            // rather than only what a server reported.
            Assert.NotNull(exchange.Duration);
            Assert.True(exchange.Duration > TimeSpan.Zero);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Without_its_secrets_the_same_capture_decodes_nothing_and_says_why()
    {
        // The Schannel case, and the single most important thing for the UI to get right:
        // the capture is perfectly good and permanently unreadable, which is a different
        // statement from "decoding failed".
        var (path, _) = TlsSessionBuilder.WriteCapture(Request, Response, embedSecrets: false);

        try
        {
            var result = new CaptureDecoder().Decode(path);

            Assert.Empty(result.Exchanges);
            Assert.Equal(1, result.Conversations);
            Assert.Equal(0, result.Decrypted);
            Assert.Equal(1, result.EncryptedWithoutKeys);

            Assert.Contains("no key in the capture", result.Summary);
            Assert.Contains("Windows' own", result.Summary);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void The_keylog_on_disk_works_when_the_capture_has_none_embedded()
    {
        // A session still running has not had its secrets written in yet, because they are
        // injected when it stops. Decoding one has to fall back to the keylog file.
        var (path, keylog) = TlsSessionBuilder.WriteCapture(Request, Response, embedSecrets: false);

        try
        {
            var result = new CaptureDecoder().Decode(path, fallbackKeylog: keylog);

            Assert.Equal(1, result.Decrypted);
            Assert.Single(result.Exchanges);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void A_connection_that_updates_its_key_keeps_decoding()
    {
        // The defect the third real run reported as "1 had a key that Keyhole could not
        // use". Either side of a TLS 1.3 connection may rotate its traffic secret
        // mid-stream, and the keylog only ever holds secret 0 — so a decoder that stops at
        // the first failure loses everything after the rotation. A browser session moving
        // tens of megabytes rotates.
        var (path, _) = TlsSessionBuilder.WriteCapture(
            System.Text.Encoding.ASCII.GetBytes(Request),
            System.Text.Encoding.ASCII.GetBytes(Response),
            embedSecrets: true,
            alpn: "http/1.1",
            keyUpdateAfterFirstRecord: true);

        try
        {
            var result = new CaptureDecoder().Decode(path);

            Assert.Equal(1, result.Decrypted);
            Assert.Equal(0, result.DecryptionFailed);

            var exchange = Assert.Single(result.Exchanges);

            // The body arrived only in the record after the update, so recovering it is
            // what proves the new key was derived rather than the stream abandoned.
            Assert.Equal(200, exchange.StatusCode);
            Assert.Equal(13, exchange.ResponseBodyBytes);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Every_tls_connection_is_accounted_for()
    {
        // The counts have to add up, because the gap is where the interesting failures
        // hide. A real run once reported "10 of 16 decrypted" with no account of the other
        // six — and those six were the ones worth looking at.
        var (withKeys, _) = TlsSessionBuilder.WriteCapture(Request, Response);
        var (withoutKeys, _) = TlsSessionBuilder.WriteCapture(Request, Response, embedSecrets: false);

        try
        {
            foreach (var path in (string[])[withKeys, withoutKeys])
            {
                var result = new CaptureDecoder().Decode(path);

                var accounted = result.Decrypted
                                + result.EncryptedWithoutKeys
                                + result.HandshakeMissing
                                + result.DecryptionFailed;

                Assert.Equal(result.Conversations, accounted);
            }
        }
        finally
        {
            File.Delete(withKeys);
            File.Delete(withoutKeys);
        }
    }

    [Fact]
    public void A_connection_whose_handshake_was_missed_is_reported_as_such()
    {
        // Distinguished from "no key" because it points somewhere else entirely: not at
        // the application's TLS stack but at the recording having missed the connection's
        // first packets. Conflating the two sent the first real investigation at the
        // decoder rather than at the capture.
        var result = new DecodeResult { Conversations = 3, HandshakeMissing = 3 };

        Assert.Contains("no handshake in the capture", result.Summary);

        // Says what is missing, not why. Both causes are plausible and the summary cannot
        // tell them apart, so naming one would send the reader looking in the wrong place.
        Assert.Contains("predate the recording", result.Summary);
        Assert.Contains("first packets were missed", result.Summary);

        Assert.DoesNotContain("Windows' own", result.Summary);
    }

    [Fact]
    public void A_key_that_opened_nothing_is_reported_as_Keyholes_problem()
    {
        // The one count here that means a bug rather than a limitation, so it must not be
        // phrased like the others.
        var result = new DecodeResult { Conversations = 1, DecryptionFailed = 1 };

        Assert.Contains("Keyhole could not use", result.Summary);
    }

    [Fact]
    public void A_missing_capture_explains_itself_rather_than_throwing()
    {
        var result = new CaptureDecoder().Decode(
            Path.Combine(Path.GetTempPath(), $"keyhole-absent-{Guid.NewGuid():N}.pcapng"));

        Assert.NotNull(result.Failure);
        Assert.Contains("Npcap", result.Failure);
        Assert.Empty(result.Exchanges);
    }

    [Fact]
    public void A_file_that_is_not_a_capture_is_reported_not_crashed()
    {
        var path = Path.Combine(Path.GetTempPath(), $"keyhole-junk-{Guid.NewGuid():N}.pcapng");
        File.WriteAllBytes(path, System.Text.Encoding.ASCII.GetBytes(new string('x', 5000)));

        try
        {
            var result = new CaptureDecoder().Decode(path);

            Assert.Empty(result.Exchanges);
            Assert.Equal(0, result.Conversations);
        }
        finally
        {
            File.Delete(path);
        }
    }

    /// <summary>
    /// The decisive check on the TLS 1.3 key schedule.
    ///
    /// Everything above would pass just as well if Keyhole's derivation were wrong in a
    /// self-consistent way — it encrypts and decrypts with the same code. tshark reads the
    /// same file and the same embedded keylog with an entirely separate implementation, so
    /// agreement means Keyhole's reading of RFC 8446 matches Wireshark's.
    /// </summary>
    [WiresharkFact]
    public void Tshark_decrypts_the_same_capture_to_the_same_request()
    {
        var tshark = PcapngWiresharkTests.WiresharkTool("tshark.exe")!;
        var (path, _) = TlsSessionBuilder.WriteCapture(Request, Response);

        try
        {
            // No keylog preference is passed: the secrets are inside the file, which is
            // the whole point of writing a Decryption Secrets Block.
            var output = Run(tshark, $"-r \"{path}\" -T fields -e http.request.full_uri " +
                                     "-e http.request.method -e http.response.code");

            Assert.Contains("GET", output);
            Assert.Contains("example.com/search?q=keyhole", output);
            Assert.Contains("200", output);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [WiresharkFact]
    public void Tshark_cannot_decrypt_the_capture_without_the_secrets_either()
    {
        // The negative half of the comparison. Without it, the test above could pass
        // because tshark was reading something other than the decrypted stream.
        var tshark = PcapngWiresharkTests.WiresharkTool("tshark.exe")!;
        var (path, _) = TlsSessionBuilder.WriteCapture(Request, Response, embedSecrets: false);

        try
        {
            var output = Run(tshark, $"-r \"{path}\" -T fields -e http.request.method");

            Assert.DoesNotContain("GET", output);
        }
        finally
        {
            File.Delete(path);
        }
    }

    /// <summary>
    /// Shared with the pcapng tests, which drain both of the child's streams at once — the
    /// only way to run tshark without risking a deadlock on whichever pipe is not being
    /// read.
    /// </summary>
    private static string Run(string executable, string arguments) =>
        PcapngWiresharkTests.Run(executable, arguments);
}
