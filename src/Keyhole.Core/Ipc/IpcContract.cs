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

    /// <summary>Set once a monitoring backend exists; null during M1.</summary>
    public string? MonitorState { get; init; }
}
