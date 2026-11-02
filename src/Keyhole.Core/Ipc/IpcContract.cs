using System.Text.Json;
using System.Text.Json.Serialization;

namespace Keyhole.Core.Ipc;

/// <summary>
/// Names shared by the pipe server and client. The pipe lives in the local namespace
/// and is ACL'd to the interactive user, so no other account can drive the service.
/// </summary>
public static class IpcChannel
{
    public const string PipeName = "keyhole.service";

    /// <summary>Frames are newline-delimited UTF-8 JSON, so a reader never needs a length prefix.</summary>
    public const byte FrameDelimiter = (byte)'\n';

    /// <summary>A single frame larger than this means a desynchronised or hostile peer.</summary>
    public const int MaxFrameBytes = 4 * 1024 * 1024;

    public static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        // Frames are newline-delimited, so indentation would corrupt framing.
        WriteIndented = false,
    };
}

/// <summary>Method names the service answers. Kept as constants so both sides share one spelling.</summary>
public static class IpcMethods
{
    public const string Ping = "ping";
    public const string GetStatus = "get-status";

    /// <summary>Aggregated per-application view — the main list.</summary>
    public const string ListApps = "list-apps";

    /// <summary>Connections for one application, for the drill-down view.</summary>
    public const string ListFlows = "list-flows";

    /// <summary>
    /// Aggregated per-destination view: which hosts are getting the most traffic,
    /// regardless of which application sent it.
    /// </summary>
    public const string ListHosts = "list-hosts";

    /// <summary>Machine-wide throughput history for the dashboard graph.</summary>
    public const string GetThroughput = "get-throughput";

    /// <summary>Every block rule the user has created.</summary>
    public const string ListRules = "list-rules";

    /// <summary>Blocks an executable. Always an explicit user action.</summary>
    public const string BlockApp = "block-app";

    /// <summary>Removes a block rule by id.</summary>
    public const string UnblockApp = "unblock-app";

    /// <summary>Enables or disables a rule without deleting it.</summary>
    public const string SetRuleEnabled = "set-rule-enabled";

    /// <summary>Launches an application with TLS key logging scoped to it alone.</summary>
    public const string StartCapture = "start-capture";

    /// <summary>Ends a capture, leaving the launched application running.</summary>
    public const string StopCapture = "stop-capture";

    /// <summary>Every capture session, running and finished.</summary>
    public const string ListCaptures = "list-captures";

    /// <summary>
    /// Decodes a session's packet capture into the requests and responses it holds.
    /// Separate from listing because it reads the whole capture file, which for a long
    /// session takes long enough that it must not be part of a routine refresh.
    /// </summary>
    public const string DecodeCapture = "decode-capture";
}

public sealed record IpcRequest
{
    public required string Method { get; init; }

    /// <summary>Correlates a response with its request; the client generates it.</summary>
    public required string Id { get; init; }

    /// <summary>Method-specific payload, deserialised by the handler that claims the method.</summary>
    public JsonElement? Params { get; init; }
}

public sealed record IpcResponse
{
    public required string Id { get; init; }
    public JsonElement? Result { get; init; }
    public IpcError? Error { get; init; }

    [JsonIgnore]
    public bool IsSuccess => Error is null;

    public static IpcResponse Ok(string id, JsonElement? result = null) =>
        new() { Id = id, Result = result };

    public static IpcResponse Fail(string id, string code, string message) =>
        new() { Id = id, Error = new IpcError { Code = code, Message = message } };
}

public sealed record IpcError
{
    public required string Code { get; init; }
    public required string Message { get; init; }
}

/// <summary>Error codes the client branches on. Anything unexpected surfaces as <see cref="Internal"/>.</summary>
public static class IpcErrorCodes
{
    public const string UnknownMethod = "unknown-method";
    public const string InvalidParams = "invalid-params";
    public const string Internal = "internal";
}

/// <summary>Answer to <see cref="IpcMethods.GetStatus"/> — enough for the UI to prove the service is live.</summary>
public sealed record ServiceStatus
{
    public required string Version { get; init; }
    public required DateTimeOffset StartedAtUtc { get; init; }
    public required bool IsElevated { get; init; }

    /// <summary>"running", "idle" before the first sample, or null when unavailable.</summary>
    public string? MonitorState { get; init; }

    /// <summary>Connections currently tracked, or null when monitoring is unavailable.</summary>
    public int? ActiveConnections { get; init; }

    /// <summary>
    /// Why byte totals read zero, as a <see cref="ReasonCodes"/> value, or null when
    /// counting works. Connection tracking runs unelevated but the ETW session does not,
    /// so the UI must be able to say why volume figures are missing instead of showing
    /// zeros that look like real measurements.
    /// </summary>
    public string? ByteCountingUnavailable { get; init; }

    /// <summary>
    /// Why blocking is unavailable, or null when rules can be created. Lets the UI
    /// disable the block button with an explanation instead of failing on click.
    /// </summary>
    public string? BlockingUnavailable { get; init; }

    /// <summary>
    /// "ready", "missing", "stopped" or "unusable".
    ///
    /// Carries the whole packet-capture story on its own, which is why there is no
    /// separate prose field: the four states are exactly the four different pieces of
    /// advice, and the UI can decide from this alone whether offering to download Npcap
    /// would actually help.
    /// </summary>
    public string? NpcapState { get; init; }

    /// <summary>Installed Npcap version, when it reports one. Not translatable.</summary>
    public string? NpcapVersion { get; init; }

    /// <summary>
    /// Why country and operator lookups are unavailable, or null when they work.
    /// One of the GeoIP <see cref="ReasonCodes"/>.
    /// </summary>
    public string? GeoIpUnavailable { get; init; }

    /// <summary>
    /// Where the GeoIP databases are looked for. A path, so it travels as data rather
    /// than inside a sentence — the UI needs to name it, and naming it is what makes the
    /// explanation actionable.
    /// </summary>
    public string? GeoIpDirectory { get; init; }
}

/// <summary>Parameters for <see cref="IpcMethods.ListFlows"/>.</summary>
public sealed record ListFlowsRequest
{
    /// <summary>
    /// Which application to drill into. Matched against the executable path, falling back
    /// to the display name for processes with no readable path.
    /// </summary>
    public required string Application { get; init; }

    /// <summary>Include connections that have already closed.</summary>
    public bool IncludeClosed { get; init; } = true;
}

/// <summary>
/// Answer to <see cref="IpcMethods.ListFlows"/>: the application's connections together
/// with its own throughput history, so the drill-down needs one round trip rather than two.
/// </summary>
public sealed record FlowsResponse
{
    public IReadOnlyList<FlowSummary> Flows { get; init; } = [];
    public IReadOnlyList<ThroughputSample> Throughput { get; init; } = [];
}

/// <summary>One row of the application list.</summary>
public sealed record AppSummary
{
    public required string DisplayName { get; init; }
    public string? ExecutablePath { get; init; }
    public string? Publisher { get; init; }
    public required string Signature { get; init; }
    public required int ActiveConnections { get; init; }
    public required int TotalConnections { get; init; }
    public required long BytesSent { get; init; }
    public required long BytesReceived { get; init; }
    public required DateTimeOffset LastActiveUtc { get; init; }
    public IReadOnlyList<string> RecentRemoteHosts { get; init; } = [];
    public IReadOnlyList<int> ProcessIds { get; init; } = [];

    /// <summary>Current upload rate in bytes per second.</summary>
    public double SentRate { get; init; }

    /// <summary>Current download rate in bytes per second.</summary>
    public double ReceivedRate { get; init; }

    /// <summary>Id of the block rule covering this app, or null when it is not blocked.</summary>
    public long? BlockedByRuleId { get; init; }
}

/// <summary>
/// One row of the host list: a destination with everything reaching it, from every
/// application at once.
/// </summary>
public sealed record HostSummary
{
    /// <summary>Resolved hostname, or the address when reverse DNS produced nothing.</summary>
    public required string Host { get; init; }

    /// <summary>
    /// Addresses seen for this host. More than one is normal behind a CDN, and the count
    /// is how the user knows the row aggregates several.
    /// </summary>
    public IReadOnlyList<string> Addresses { get; init; } = [];

    public IReadOnlyList<int> Ports { get; init; } = [];

    /// <summary>
    /// Applications talking to this host. The interesting figure: one destination shared
    /// by several unrelated programs is worth a second look.
    /// </summary>
    public IReadOnlyList<string> Applications { get; init; } = [];

    public required int ActiveConnections { get; init; }
    public required int TotalConnections { get; init; }
    public required long BytesSent { get; init; }
    public required long BytesReceived { get; init; }
    public required DateTimeOffset LastActiveUtc { get; init; }

    /// <summary>
    /// Where this destination is, from the first of its addresses that resolves. One host
    /// can span countries behind a CDN, but the column answers "roughly where is this",
    /// and picking one is more useful than listing several.
    /// </summary>
    public EndpointLocation? Location { get; init; }
}

/// <summary>Parameters for <see cref="IpcMethods.BlockApp"/>.</summary>
public sealed record BlockAppRequest
{
    public required string ExecutablePath { get; init; }

    /// <summary>"outbound", "inbound" or "both". Outbound is what blocking usually means.</summary>
    public string Direction { get; init; } = "outbound";

    public string? Note { get; init; }
}

/// <summary>Parameters for <see cref="IpcMethods.UnblockApp"/>.</summary>
public sealed record UnblockAppRequest
{
    public required long RuleId { get; init; }
}

/// <summary>Parameters for <see cref="IpcMethods.SetRuleEnabled"/>.</summary>
public sealed record SetRuleEnabledRequest
{
    public required long RuleId { get; init; }
    public required bool Enabled { get; init; }
}

/// <summary>Parameters for <see cref="IpcMethods.StartCapture"/>.</summary>
public sealed record StartCaptureRequest
{
    public required string ExecutablePath { get; init; }

    /// <summary>Command line passed through to the application.</summary>
    public string? Arguments { get; init; }
}

/// <summary>Parameters for <see cref="IpcMethods.StopCapture"/>.</summary>
public sealed record StopCaptureRequest
{
    public required long SessionId { get; init; }
}

/// <summary>One capture session as the UI sees it.</summary>
public sealed record CaptureSummary
{
    public required long Id { get; init; }
    public required string DisplayName { get; init; }
    public required string ExecutablePath { get; init; }
    public int? ProcessId { get; init; }
    public required string Directory { get; init; }
    public required string KeylogFile { get; init; }
    public required DateTimeOffset StartedUtc { get; init; }
    public DateTimeOffset? StoppedUtc { get; init; }
    public required bool IsRunning { get; init; }

    /// <summary>
    /// Bytes written to the keylog. Zero on a running capture means the application is
    /// not writing secrets — almost always because it uses Schannel rather than NSS or
    /// OpenSSL, which is worth telling the user rather than leaving them waiting.
    /// </summary>
    public required long KeylogBytes { get; init; }

    /// <summary>"likely" or "unknown" — whether this executable tends to honour the variable.</summary>
    public required string KeylogSupport { get; init; }

    /// <summary>
    /// This session's packet capture, or null when none was recorded. A session with keys
    /// but no packets is what every capture was before M8, and is still what happens on a
    /// machine without Npcap.
    /// </summary>
    public string? PcapFile { get; init; }

    /// <summary>Size of the capture file on disk.</summary>
    public long PcapBytes { get; init; }

    /// <summary>
    /// Why this session is not recording packets, as a <see cref="ReasonCodes"/> value, or
    /// null when it is. Carries the reason all the way to the UI so a keylog-only session
    /// explains itself instead of showing an empty packet count.
    /// </summary>
    public string? RecordingIssue { get; init; }

    /// <summary>
    /// The size ceiling in megabytes, present when <see cref="RecordingIssue"/> says the
    /// limit was reached. A number, so the UI can say which limit without the service
    /// composing the sentence.
    /// </summary>
    public int? SizeLimitMegabytes { get; init; }
}

/// <summary>Parameters for <see cref="IpcMethods.DecodeCapture"/>.</summary>
public sealed record DecodeCaptureRequest
{
    public required long SessionId { get; init; }
}

/// <summary>
/// Answer to <see cref="IpcMethods.DecodeCapture"/>: what the application actually asked
/// for, and an account of whatever could not be read.
/// </summary>
public sealed record DecodeCaptureResponse
{
    public IReadOnlyList<ExchangeSummary> Exchanges { get; init; } = [];

    /// <summary>TCP connections carrying TLS in the capture.</summary>
    public int Conversations { get; init; }

    /// <summary>How many of those were decrypted.</summary>
    public int Decrypted { get; init; }

    /// <summary>
    /// How many carried TLS the capture holds no key for. Almost always an application on
    /// Windows' own TLS stack, which ignores SSLKEYLOGFILE.
    /// </summary>
    public int EncryptedWithoutKeys { get; init; }

    /// <summary>
    /// How many were already open when recording started, so their handshake — and with it
    /// the only thing that identifies them — is not in the capture.
    /// </summary>
    public int HandshakeMissing { get; init; }

    /// <summary>
    /// How many had a key that still opened nothing. The one figure here that means a bug
    /// in Keyhole rather than a limit of what was recorded.
    /// </summary>
    public int DecryptionFailed { get; init; }

    /// <summary>
    /// Why nothing could be decoded at all, as a <see cref="ReasonCodes"/> value, or null
    /// when the pass ran.
    /// </summary>
    public string? Failure { get; init; }

    /// <summary>
    /// Bytes of QUIC traffic recorded. Reported because it is the most likely reason a
    /// browser capture looks emptier than expected, and because the UI composes that
    /// sentence itself.
    /// </summary>
    public long QuicBytes { get; init; }

    /// <summary>
    /// How many exchanges were dropped to fit the answer in one IPC frame, or zero when
    /// none were. A number rather than a sentence, so the UI can phrase the truncation.
    /// </summary>
    public int Truncated { get; init; }
}

/// <summary>One request and its response, as the UI shows it.</summary>
public sealed record ExchangeSummary
{
    public required string Protocol { get; init; }
    public required string Method { get; init; }
    public required string Url { get; init; }
    public int? StatusCode { get; init; }
    public string? ContentType { get; init; }
    public required long RequestBytes { get; init; }
    public required long ResponseBytes { get; init; }
    public required DateTimeOffset RequestedUtc { get; init; }

    /// <summary>Request to response, in milliseconds, or null when no response arrived.</summary>
    public double? DurationMs { get; init; }

    /// <summary>
    /// Why this exchange is only partly recovered, as a <see cref="ReasonCodes"/> value,
    /// or null when it is whole.
    /// </summary>
    public string? Incomplete { get; init; }

    public IReadOnlyList<HeaderPair> RequestHeaders { get; init; } = [];
    public IReadOnlyList<HeaderPair> ResponseHeaders { get; init; } = [];
}

/// <summary>One header. A pair rather than a map: order and duplicates both carry meaning.</summary>
public sealed record HeaderPair(string Name, string Value);

/// <summary>One sample of machine-wide throughput, in bytes per second.</summary>
public sealed record ThroughputSample
{
    public required DateTimeOffset TimestampUtc { get; init; }
    public required double SentPerSecond { get; init; }
    public required double ReceivedPerSecond { get; init; }
}

/// <summary>One block rule as the UI sees it.</summary>
public sealed record RuleSummary
{
    public required long Id { get; init; }
    public required string DisplayName { get; init; }
    public required string ExecutablePath { get; init; }
    public required string Direction { get; init; }
    public required bool IsEnabled { get; init; }
    public string? Note { get; init; }
    public required DateTimeOffset CreatedUtc { get; init; }

    /// <summary>
    /// "match", "changed" or "unknown". "changed" means a different binary now sits at
    /// the blocked path than the one the rule was created for.
    /// </summary>
    public required string ExecutableState { get; init; }
}

/// <summary>
/// Where a remote endpoint is and who operates its network, from the offline GeoIP
/// databases.
///
/// Every field is optional and the whole record is null when nothing is known: the country
/// and ASN databases are separate files, a user may have one and not the other, and a
/// private address has neither. A blank column is the honest rendering of "no data"; an
/// "unknown" placeholder on every row is not.
/// </summary>
public sealed record EndpointLocation
{
    /// <summary>Two-letter ISO code, for a compact column.</summary>
    public string? CountryCode { get; init; }

    /// <summary>The readable name, for a tooltip.</summary>
    public string? CountryName { get; init; }

    public long? AutonomousSystemNumber { get; init; }

    /// <summary>Who operates the network — usually more telling than the country.</summary>
    public string? Organisation { get; init; }
}

/// <summary>One connection in the drill-down view.</summary>
public sealed record FlowSummary
{
    public required int ProcessId { get; init; }
    public required string Protocol { get; init; }
    public required string LocalAddress { get; init; }
    public required int LocalPort { get; init; }
    public required string RemoteAddress { get; init; }
    public required int RemotePort { get; init; }
    public string? RemoteHostname { get; init; }
    public required string State { get; init; }
    public required long BytesSent { get; init; }
    public required long BytesReceived { get; init; }
    public required DateTimeOffset StartedUtc { get; init; }
    public required DateTimeOffset LastSeenUtc { get; init; }
    public DateTimeOffset? EndedUtc { get; init; }
    public bool IsActive => EndedUtc is null;

    /// <summary>
    /// Where the remote end is, or null when no GeoIP database is installed and for
    /// addresses that never left the local network.
    /// </summary>
    public EndpointLocation? Location { get; init; }
}
