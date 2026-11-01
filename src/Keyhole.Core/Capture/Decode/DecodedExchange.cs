namespace Keyhole.Core.Capture.Decode;

/// <summary>
/// One request and its response, recovered from a capture.
///
/// This is what M8 exists to produce. Everything before it says who an application talked
/// to; this says what it asked for and what came back.
/// </summary>
public sealed record DecodedExchange
{
    /// <summary>Which conversation this came from, as address:port pairs.</summary>
    public required string Conversation { get; init; }

    /// <summary>"HTTP/1.1" or "HTTP/2".</summary>
    public required string Protocol { get; init; }

    public required string Method { get; init; }

    /// <summary>
    /// The full URL where the authority is known. HTTP/2 carries it in :authority and
    /// :scheme; HTTP/1.1 only has a Host header and a path, and may have neither.
    /// </summary>
    public required string Url { get; init; }

    /// <summary>Status code, or null when no response was captured.</summary>
    public int? StatusCode { get; init; }

    public IReadOnlyList<HttpHeader> RequestHeaders { get; init; } = [];

    public IReadOnlyList<HttpHeader> ResponseHeaders { get; init; } = [];

    /// <summary>Request body size in bytes, as captured.</summary>
    public long RequestBodyBytes { get; init; }

    /// <summary>Response body size in bytes, as captured.</summary>
    public long ResponseBodyBytes { get; init; }

    /// <summary>When the request's first byte was seen.</summary>
    public required DateTimeOffset RequestedUtc { get; init; }

    /// <summary>When the response's last byte was seen, or null when none arrived.</summary>
    public DateTimeOffset? RespondedUtc { get; init; }

    /// <summary>
    /// Time from the request's first byte to the response's last, or null when no response
    /// was captured. Measured from the capture's own timestamps, so it includes network
    /// time rather than only server time.
    /// </summary>
    public TimeSpan? Duration =>
        RespondedUtc is { } responded ? responded - RequestedUtc : null;

    /// <summary>
    /// Content type from the response, for the UI to show without the user opening headers.
    /// </summary>
    public string? ContentType =>
        ResponseHeaders.FirstOrDefault(h =>
            h.Name.Equals("content-type", StringComparison.OrdinalIgnoreCase))?.Value;

    /// <summary>
    /// Set when the exchange was recovered only in part — a response still arriving when
    /// the capture stopped, or a body the size cap truncated. Says so rather than
    /// presenting a partial exchange as whole.
    /// </summary>
    public string? Incomplete { get; init; }
}

/// <summary>One header, kept as a pair because order and duplicates both carry meaning.</summary>
public sealed record HttpHeader(string Name, string Value);

/// <summary>
/// Everything a decode pass produced, including what it could not do.
///
/// The failures matter as much as the results. A capture of a Schannel application yields
/// nothing and that is expected; a capture full of QUIC yields nothing for a different
/// reason entirely. Reporting "0 requests" for both would make the feature look broken in
/// one case and working in the other, when the truth is the reverse.
/// </summary>
public sealed record DecodeResult
{
    public IReadOnlyList<DecodedExchange> Exchanges { get; init; } = [];

    /// <summary>TCP conversations seen in the capture.</summary>
    public int Conversations { get; init; }

    /// <summary>Conversations whose TLS was decrypted.</summary>
    public int Decrypted { get; init; }

    /// <summary>
    /// Conversations carrying TLS that could not be decrypted, because the capture held no
    /// secret for them. Almost always a Schannel application, which ignores SSLKEYLOGFILE.
    /// </summary>
    public int EncryptedWithoutKeys { get; init; }

    /// <summary>
    /// Conversations whose handshake was not in the capture, so nothing identifies them.
    ///
    /// Counted separately because it points somewhere quite different from the other
    /// failures: not at the application's TLS stack, but at the recording having started
    /// late or dropped the connection's first packets. The first real browser run was
    /// almost entirely this, and reporting it as "could not decrypt" would have pointed
    /// the investigation at the decoder instead of the capture.
    /// </summary>
    public int HandshakeMissing { get; init; }

    /// <summary>
    /// Conversations where a key was present and still opened nothing.
    ///
    /// Unlike every other count here, this one means a bug in Keyhole rather than a
    /// limitation of what was captured — which is exactly why it must not be folded in
    /// with the rest.
    /// </summary>
    public int DecryptionFailed { get; init; }

    /// <summary>
    /// Bytes of UDP traffic on port 443, which is QUIC and therefore HTTP/3.
    ///
    /// Reported because it is the single most likely reason a browser capture looks
    /// emptier than expected: Chrome prefers HTTP/3 where a server offers it, and Keyhole
    /// does not decode QUIC. Silence about this would read as a decoding failure.
    /// </summary>
    public long QuicBytes { get; init; }

    /// <summary>Why nothing could be decoded at all, or null when the pass ran.</summary>
    public string? Failure { get; init; }

    /// <summary>
    /// A sentence summarising what was and was not recovered, for the UI to show above
    /// the request list.
    /// </summary>
    public string Summary => Failure ?? BuildSummary();

    private string BuildSummary()
    {
        var parts = new List<string>
        {
            Exchanges.Count == 1 ? "1 request" : $"{Exchanges.Count} requests",
        };

        if (Decrypted > 0)
        {
            parts.Add($"{Decrypted} of {Conversations} TLS connections decrypted");
        }
        else if (Conversations > 0)
        {
            parts.Add($"none of {Conversations} connections could be decrypted");
        }

        if (EncryptedWithoutKeys > 0)
        {
            parts.Add(
                $"{EncryptedWithoutKeys} had no key in the capture (these use Windows' own " +
                "TLS, which ignores SSLKEYLOGFILE)");
        }

        if (HandshakeMissing > 0)
        {
            // Deliberately says what is missing rather than why. The handshake can be
            // absent because the connection predates the recording, or because its first
            // packets were missed during a burst of new connections — and a summary that
            // picks one of those sends the reader looking in the wrong place. An earlier
            // version asserted the first, which was the less likely of the two.
            parts.Add(
                $"{HandshakeMissing} had no handshake in the capture, so nothing identified " +
                "them (either they predate the recording or their first packets were missed)");
        }

        if (DecryptionFailed > 0)
        {
            // Phrased as Keyhole's problem because it is one: the key was there.
            parts.Add($"{DecryptionFailed} had a key that Keyhole could not use");
        }

        if (QuicBytes > 0)
        {
            parts.Add(
                $"{QuicBytes / 1024} KB of QUIC/HTTP3 was recorded but cannot be decoded");
        }

        return string.Join("; ", parts) + ".";
    }

    public static DecodeResult Failed(string reason) => new() { Failure = reason };
}
