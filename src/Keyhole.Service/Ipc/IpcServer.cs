using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Keyhole.Core.Ipc;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Keyhole.Service.Ipc;

/// <summary>
/// Hosts the named pipe the UI talks to. One connection is served at a time, which is
/// plenty: the UI issues infrequent control calls, and serialising them keeps rule writes
/// free of races by construction.
/// </summary>
public sealed class IpcServer(
    IEnumerable<IIpcMethodHandler> handlers,
    ILogger<IpcServer> logger) : BackgroundService
{
    private readonly Dictionary<string, IIpcMethodHandler> _handlers =
        handlers.ToDictionary(h => h.Method, StringComparer.Ordinal);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation(
            "IPC server listening on \\\\.\\pipe\\{PipeName} with {HandlerCount} methods: {Methods}",
            IpcChannel.PipeName,
            _handlers.Count,
            string.Join(", ", _handlers.Keys.Order()));

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ServeOneConnectionAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                // A single bad client must never take the service down; log and keep listening.
                logger.LogError(ex, "IPC connection failed; continuing to listen.");
                await Task.Delay(TimeSpan.FromMilliseconds(250), stoppingToken).ConfigureAwait(false);
            }
        }

        logger.LogInformation("IPC server stopped.");
    }

    private async Task ServeOneConnectionAsync(CancellationToken ct)
    {
        await using var pipe = CreateServerStream();
        await pipe.WaitForConnectionAsync(ct).ConfigureAwait(false);

        var request = await IpcFraming.ReadFrameAsync<IpcRequest>(pipe, ct).ConfigureAwait(false);
        if (request is null)
        {
            // Client connected then went away without asking anything.
            return;
        }

        var response = await DispatchAsync(request, ct).ConfigureAwait(false);
        await IpcFraming.WriteFrameAsync(pipe, response, ct).ConfigureAwait(false);

        await DrainBeforeCloseAsync(pipe, request.Method, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Waits for the client to read the response before the stream is disposed.
    /// Tearing down a named pipe server discards whatever the client has not read yet, so
    /// skipping this loses short responses whenever the client is a moment late.
    /// </summary>
    private async Task DrainBeforeCloseAsync(NamedPipeServerStream pipe, string method, CancellationToken ct)
    {
        // WaitForPipeDrain blocks forever if the client never reads. Only one connection is
        // served at a time, so a hung client would otherwise freeze the whole service.
        var drain = Task.Run(() =>
        {
            if (pipe.IsConnected)
            {
                pipe.WaitForPipeDrain();
            }
        }, ct);

        try
        {
            await drain.WaitAsync(DrainTimeout, ct).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            logger.LogWarning(
                "Client did not read the response to '{Method}' within {Timeout}; closing anyway.",
                method, DrainTimeout);
        }
    }

    private static readonly TimeSpan DrainTimeout = TimeSpan.FromSeconds(5);

    private async Task<IpcResponse> DispatchAsync(IpcRequest request, CancellationToken ct)
    {
        if (!_handlers.TryGetValue(request.Method, out var handler))
        {
            logger.LogWarning("Rejected unknown IPC method '{Method}'.", request.Method);
            return IpcResponse.Fail(
                request.Id, IpcErrorCodes.UnknownMethod, $"No handler for method '{request.Method}'.");
        }

        try
        {
            var result = await handler.HandleAsync(request.Params, ct).ConfigureAwait(false);
            logger.LogDebug("Handled IPC method '{Method}'.", request.Method);
            return IpcResponse.Ok(request.Id, result);
        }
        catch (IpcInvalidParamsException ex)
        {
            return IpcResponse.Fail(request.Id, IpcErrorCodes.InvalidParams, ex.Message);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(ex, "IPC method '{Method}' threw.", request.Method);

            // Deliberately generic: the service is elevated, so internal detail stays in the log.
            return IpcResponse.Fail(
                request.Id, IpcErrorCodes.Internal, $"Method '{request.Method}' failed. See service log.");
        }
    }

    /// <summary>
    /// Creates the pipe with an explicit ACL. The service runs elevated, so an unrestricted
    /// pipe would let any local account issue privileged calls. Only interactive users and
    /// administrators may connect; everything else, including NETWORK, is denied by omission.
    /// </summary>
    private static NamedPipeServerStream CreateServerStream()
    {
        var security = new PipeSecurity();

        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.InteractiveSid, null),
            PipeAccessRights.ReadWrite,
            AccessControlType.Allow));

        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Allow));

        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Allow));

        return NamedPipeServerStreamAcl.Create(
            pipeName: IpcChannel.PipeName,
            direction: PipeDirection.InOut,
            maxNumberOfServerInstances: 1,
            transmissionMode: PipeTransmissionMode.Byte,
            // Not CurrentUserOnly: the service runs as LocalSystem while the UI runs as the
            // interactive user, so ownership would never match. The ACL above is the control.
            options: PipeOptions.Asynchronous,
            inBufferSize: 64 * 1024,
            outBufferSize: 64 * 1024,
            pipeSecurity: security);
    }
}

/// <summary>Answers <see cref="IpcMethods.Ping"/> with no payload — liveness only.</summary>
public sealed class PingHandler : IIpcMethodHandler
{
    public string Method => IpcMethods.Ping;

    public Task<JsonElement?> HandleAsync(JsonElement? parameters, CancellationToken ct) =>
        Task.FromResult<JsonElement?>(null);
}

/// <summary>Answers <see cref="IpcMethods.GetStatus"/> with enough for the UI to show a live badge.</summary>
public sealed class GetStatusHandler(ServiceRuntimeInfo runtime) : IIpcMethodHandler
{
    public string Method => IpcMethods.GetStatus;

    public Task<JsonElement?> HandleAsync(JsonElement? parameters, CancellationToken ct)
    {
        var status = new ServiceStatus
        {
            Version = runtime.Version,
            StartedAtUtc = runtime.StartedAtUtc,
            IsElevated = runtime.IsElevated,
            MonitorState = null, // No monitoring backend until M2.
        };

        return Task.FromResult<JsonElement?>(JsonSerializer.SerializeToElement(status, IpcChannel.Json));
    }
}
