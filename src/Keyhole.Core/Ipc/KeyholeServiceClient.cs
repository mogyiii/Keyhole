using System.IO.Pipes;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Keyhole.Core.Ipc;

/// <summary>
/// Client half of the service pipe. Opens a fresh connection per call: calls are rare and
/// small during M1, and a short-lived connection removes any reconnect state machine.
/// </summary>
public sealed class KeyholeServiceClient(ILogger<KeyholeServiceClient>? logger = null)
{
    private readonly ILogger _logger = logger ?? NullLogger<KeyholeServiceClient>.Instance;

    public static TimeSpan DefaultConnectTimeout => TimeSpan.FromSeconds(3);

    public async Task<bool> PingAsync(CancellationToken ct = default)
    {
        try
        {
            await InvokeAsync<object?>(IpcMethods.Ping, null, ct).ConfigureAwait(false);
            return true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogDebug(ex, "Ping failed; treating the service as unavailable.");
            return false;
        }
    }

    public Task<ServiceStatus> GetStatusAsync(CancellationToken ct = default) =>
        InvokeAsync<ServiceStatus>(IpcMethods.GetStatus, null, ct);

    /// <summary>Aggregated per-application activity — the main list.</summary>
    public Task<IReadOnlyList<AppSummary>> ListAppsAsync(CancellationToken ct = default) =>
        InvokeAsync<IReadOnlyList<AppSummary>>(IpcMethods.ListApps, null, ct);

    /// <summary>
    /// Connections belonging to one application. <paramref name="application"/> is the
    /// executable path from <see cref="AppSummary"/>, or its display name when there is none.
    /// </summary>
    public Task<IReadOnlyList<FlowSummary>> ListFlowsAsync(
        string application,
        bool includeClosed = true,
        CancellationToken ct = default) =>
        InvokeAsync<IReadOnlyList<FlowSummary>>(
            IpcMethods.ListFlows,
            new ListFlowsRequest { Application = application, IncludeClosed = includeClosed },
            ct);

    /// <summary>
    /// Sends one request and returns its deserialised result.
    /// </summary>
    /// <exception cref="ServiceUnavailableException">The service is not running or not reachable.</exception>
    /// <exception cref="ServiceCallException">The service answered with an error.</exception>
    public async Task<TResult> InvokeAsync<TResult>(
        string method,
        object? parameters,
        CancellationToken ct = default)
    {
        await using var pipe = new NamedPipeClientStream(
            serverName: ".",
            pipeName: IpcChannel.PipeName,
            direction: PipeDirection.InOut,
            options: PipeOptions.Asynchronous);

        try
        {
            await pipe.ConnectAsync((int)DefaultConnectTimeout.TotalMilliseconds, ct).ConfigureAwait(false);
        }
        catch (TimeoutException ex)
        {
            throw new ServiceUnavailableException(
                "Keyhole service did not accept a connection. Is it installed and running?", ex);
        }
        catch (IOException ex)
        {
            throw new ServiceUnavailableException("Keyhole service pipe could not be opened.", ex);
        }

        var request = new IpcRequest
        {
            Id = Guid.NewGuid().ToString("n"),
            Method = method,
            Params = parameters is null ? null : JsonSerializer.SerializeToElement(parameters, IpcChannel.Json),
        };

        await IpcFraming.WriteFrameAsync(pipe, request, ct).ConfigureAwait(false);

        var response = await IpcFraming.ReadFrameAsync<IpcResponse>(pipe, ct).ConfigureAwait(false)
                       ?? throw new ServiceUnavailableException("Service closed the pipe without answering.");

        if (response.Id != request.Id)
        {
            throw new ServiceCallException(
                IpcErrorCodes.Internal,
                $"Response id '{response.Id}' did not match request id '{request.Id}'.");
        }

        if (response.Error is { } error)
        {
            throw new ServiceCallException(error.Code, error.Message);
        }

        // A void method legitimately returns no payload.
        if (response.Result is null or { ValueKind: JsonValueKind.Null })
        {
            return default!;
        }

        return response.Result.Value.Deserialize<TResult>(IpcChannel.Json)
               ?? throw new ServiceCallException(IpcErrorCodes.Internal, "Result deserialised to null.");
    }
}

public sealed class ServiceUnavailableException : Exception
{
    public ServiceUnavailableException(string message) : base(message) { }
    public ServiceUnavailableException(string message, Exception inner) : base(message, inner) { }
}

public sealed class ServiceCallException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}
