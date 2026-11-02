namespace Keyhole.Core.Ipc;

/// <summary>
/// The reasons the service reports, as codes rather than sentences.
///
/// The service used to send finished English prose and the UI showed it verbatim. That
/// works until the interface has to exist in another language, at which point half of it
/// is English — and the English half is exactly the explanatory text, which is where a
/// user most needs their own language.
///
/// So the service says *what* is wrong and the UI says it in words. Anything that is not
/// translatable — a path, a version, a size — travels as its own field next to the code,
/// never embedded in it.
///
/// The service still logs full English sentences. Logs are for whoever is debugging, and
/// an English log is easier to search and to paste into an issue than a localised one.
/// </summary>
public static class ReasonCodes
{
    /// <summary>
    /// The service is not running elevated. The single most common answer, and the one
    /// the user can actually act on.
    /// </summary>
    public const string NotElevated = "not-elevated";

    // --- byte counting ------------------------------------------------------------

    /// <summary>The ETW session could not be created or stopped unexpectedly.</summary>
    public const string EtwUnavailable = "etw-unavailable";

    // --- blocking ----------------------------------------------------------------

    /// <summary>The Windows Firewall COM interface could not be reached at all.</summary>
    public const string FirewallUnreachable = "firewall-unreachable";

    /// <summary>There is no file at the path that was to be blocked.</summary>
    public const string BlockNoExecutable = "block-no-executable";

    /// <summary>
    /// The rule the user acted on is not in the database. Normal rather than exceptional:
    /// two windows, or a rule removed while its row was still on screen.
    /// </summary>
    public const string BlockNoRule = "block-no-rule";

    /// <summary>
    /// The firewall accepted the request and failed to carry it out. Distinct from
    /// <see cref="FirewallUnreachable"/>: the interface was there, the operation was not
    /// refused for want of rights, and it still did not happen — so the advice is not
    /// "elevate" but "look at the log".
    /// </summary>
    public const string BlockRuleFailed = "block-rule-failed";

    // --- GeoIP -------------------------------------------------------------------

    /// <summary>Neither database is present.</summary>
    public const string GeoIpNoDatabase = "geoip-none";

    /// <summary>The ASN database is there but the country one is not.</summary>
    public const string GeoIpNoCountryDatabase = "geoip-no-country";

    /// <summary>The country database is there but the ASN one is not.</summary>
    public const string GeoIpNoAsnDatabase = "geoip-no-asn";

    // --- packet recording --------------------------------------------------------

    /// <summary>Npcap is not usable, so the session collects keys only.</summary>
    public const string RecordingNoNpcap = "recording-no-npcap";

    /// <summary>Npcap is there but no adapter could be opened.</summary>
    public const string RecordingNoAdapter = "recording-no-adapter";

    /// <summary>The capture file could not be created.</summary>
    public const string RecordingFileError = "recording-file-error";

    /// <summary>
    /// Recording stopped at the configured size ceiling. The capture is a prefix of the
    /// session, which changes what can be concluded from it.
    /// </summary>
    public const string RecordingSizeLimit = "recording-size-limit";

    /// <summary>The application wrote no TLS secrets, so the capture cannot be decrypted.</summary>
    public const string RecordingNoSecrets = "recording-no-secrets";

    /// <summary>
    /// The secrets exist but could not be written into the capture file. They are still in
    /// the keylog beside it, so this is a degradation rather than a loss.
    /// </summary>
    public const string RecordingSecretsNotEmbedded = "recording-secrets-not-embedded";

    // --- decoding ----------------------------------------------------------------

    /// <summary>This session recorded no packets, so there is nothing to decode.</summary>
    public const string DecodeNoCapture = "decode-no-capture";

    /// <summary>The capture file is gone.</summary>
    public const string DecodeFileMissing = "decode-file-missing";

    /// <summary>The capture file could not be read.</summary>
    public const string DecodeUnreadable = "decode-unreadable";

    /// <summary>More connections than the decoder will hold at once; only the first were read.</summary>
    public const string DecodeTooManyConversations = "decode-too-many";

    /// <summary>Decoding threw. A bug, and reported as one rather than as a limitation.</summary>
    public const string DecodeFailed = "decode-failed";

    // --- one exchange ------------------------------------------------------------

    /// <summary>No response was captured for this request.</summary>
    public const string ExchangeNoResponse = "exchange-no-response";

    /// <summary>The response was still arriving when the capture ended.</summary>
    public const string ExchangeResponseTruncated = "exchange-response-truncated";

    /// <summary>The body was cut off when the capture ended.</summary>
    public const string ExchangeBodyTruncated = "exchange-body-truncated";

    /// <summary>
    /// Header decompression failed, so this connection's later headers cannot be trusted
    /// either: HPACK is stateful.
    /// </summary>
    public const string ExchangeHeadersBroken = "exchange-headers-broken";

    // --- starting a capture ------------------------------------------------------

    /// <summary>There is no file at the path the user picked.</summary>
    public const string CaptureNoExecutable = "capture-no-executable";

    /// <summary>The application could not be started.</summary>
    public const string CaptureLaunchFailed = "capture-launch-failed";
}
