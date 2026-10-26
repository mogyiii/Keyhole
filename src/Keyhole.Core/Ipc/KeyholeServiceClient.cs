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
    public Task<FlowsResponse> ListFlowsAsync(
        string application,
        bool includeClosed = true,
        CancellationToken ct = default) =>
        InvokeAsync<FlowsResponse>(
            IpcMethods.ListFlows,
            new ListFlowsRequest { Application = application, IncludeClosed = includeClosed },
            ct);

    /// <summary>Machine-wide throughput history for the dashboard graph.</summary>
    public Task<IReadOnlyList<ThroughputSample>> GetThroughputAsync(CancellationToken ct = default) =>
        InvokeAsync<IReadOnlyList<ThroughputSample>>(IpcMethods.GetThroughput, null, ct);

    public Task<IReadOnlyList<RuleSummary>> ListRulesAsync(CancellationToken ct = default) =>
        InvokeAsync<IReadOnlyList<RuleSummary>>(IpcMethods.ListRules, null, ct);

    /// <summary>Blocks an executable. Always the result of an explicit user action.</summary>
    public Task<RuleSummary> BlockAppAsync(
        string executablePath,
        string direction = "outbound",
        string? note = null,
        CancellationToken ct = default) =>
        InvokeAsync<RuleSummary>(
            IpcMethods.BlockApp,
            new BlockAppRequest { ExecutablePath = executablePath, Direction = direction, Note = note },
            ct);

    public Task UnblockAppAsync(long ruleId, CancellationToken ct = default) =>
        InvokeAsync<object>(IpcMethods.UnblockApp, new UnblockAppRequest { RuleId = ruleId }, ct);

    public Task<IReadOnlyList<CaptureSummary>> ListCapturesAsync(CancellationToken ct = default) =>
        InvokeAsync<IReadOnlyList<CaptureSummary>>(IpcMethods.ListCaptures, null, ct);

    /// <summary>
    /// Launches an application with TLS key logging scoped to it alone — no machine-wide
    /// environment variable, nothing to unset afterwards.
    /// </summary>
    public Task<CaptureSummary> StartCaptureAsync(
        string executablePath,
        string? arguments = null,
        CancellationToken ct = default) =>
        InvokeAsync<CaptureSummary>(
            IpcMethods.StartCapture,
            new StartCaptureRequest { ExecutablePath = executablePath, Arguments = arguments },
            ct);

    public Task StopCaptureAsync(long sessionId, CancellationToken ct = default) =>
        InvokeAsync<object>(IpcMethods.StopCapture, new StopCaptureRequest { SessionId = sessionId }, ct);

    public Task<RuleSummary> SetRuleEnabledAsync(long ruleId, bool enabled, CancellationToken ct = default) =>
        InvokeAsync<RuleSummary>(
            IpcMethods.SetRuleEnabled,
            new SetRuleEnabledRequest { RuleId = ruleId, Enabled = enabled },
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
