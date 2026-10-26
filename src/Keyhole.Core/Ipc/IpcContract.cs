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
    /// Why byte totals read zero, or null when counting works. Connection tracking runs
    /// unelevated but the ETW session does not, so the UI must be able to say why volume
    /// figures are missing instead of showing zeros that look like real measurements.
    /// </summary>
    public string? ByteCountingUnavailableReason { get; init; }

    /// <summary>
    /// Why blocking is unavailable, or null when rules can be created. Lets the UI
    /// disable the block button with an explanation instead of failing on click.
    /// </summary>
    public string? BlockingUnavailableReason { get; init; }
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
}

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
}
