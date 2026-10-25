using System.Text.Json;

namespace Keyhole.Core.Ipc;

/// <summary>
/// One server-side method. Implementations are registered in DI and matched by
/// <see cref="Method"/>, so adding a capability never touches the dispatch loop.
/// </summary>
public interface IIpcMethodHandler
{
    /// <summary>Method name from <see cref="IpcMethods"/>.</summary>
    string Method { get; }

    /// <summary>
    /// Handles a call. Returning null means "no payload". Throwing <see cref="IpcInvalidParamsException"/>
    /// maps to a structured error; any other exception becomes an internal error.
    /// </summary>
    Task<JsonElement?> HandleAsync(JsonElement? parameters, CancellationToken ct);
}

public sealed class IpcInvalidParamsException(string message) : Exception(message);
