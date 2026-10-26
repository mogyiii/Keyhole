using System.Text.Json;
using Keyhole.Core.Capture;
using Keyhole.Core.Ipc;

namespace Keyhole.Service.Ipc;

/// <summary>Answers <see cref="IpcMethods.ListCaptures"/> with every capture session.</summary>
public sealed class ListCapturesHandler(CaptureService capture) : IIpcMethodHandler
{
    public string Method => IpcMethods.ListCaptures;

    public Task<JsonElement?> HandleAsync(JsonElement? parameters, CancellationToken ct)
    {
        var sessions = capture.ListSessions().Select(s => ToSummary(capture, s)).ToList();

        return Task.FromResult<JsonElement?>(JsonSerializer.SerializeToElement(sessions, IpcChannel.Json));
    }

    internal static CaptureSummary ToSummary(CaptureService capture, CaptureSession session) => new()
    {
        Id = session.Id,
        DisplayName = session.DisplayName,
        ExecutablePath = session.ExecutablePath,
        ProcessId = session.ProcessId,
        Directory = session.Directory,
        KeylogFile = session.KeylogFile,
        StartedUtc = session.StartedUtc,
        StoppedUtc = session.StoppedUtc,
        IsRunning = session.IsRunning,
        KeylogBytes = capture.GetKeylogSize(session.KeylogFile),
        KeylogSupport = CaptureService.SupportsKeylog(session.ExecutablePath)
            .ToString()
            .ToLowerInvariant(),
    };
}

/// <summary>Answers <see cref="IpcMethods.StartCapture"/>. Always an explicit user action.</summary>
public sealed class StartCaptureHandler(CaptureService capture) : IIpcMethodHandler
{
    public string Method => IpcMethods.StartCapture;

    public Task<JsonElement?> HandleAsync(JsonElement? parameters, CancellationToken ct)
    {
        var request = IpcParams.Parse<StartCaptureRequest>(parameters, Method);

        if (string.IsNullOrWhiteSpace(request.ExecutablePath))
        {
            throw new IpcInvalidParamsException("'executablePath' must not be empty.");
        }

        try
        {
            var session = capture.Start(request.ExecutablePath, request.Arguments);

            return Task.FromResult<JsonElement?>(
                JsonSerializer.SerializeToElement(
                    ListCapturesHandler.ToSummary(capture, session), IpcChannel.Json));
        }
        catch (CaptureException ex)
        {
            // Carries a user-facing reason, so it must reach the UI intact.
            throw new IpcInvalidParamsException(ex.Message);
        }
    }
}

/// <summary>Answers <see cref="IpcMethods.StopCapture"/>.</summary>
public sealed class StopCaptureHandler(CaptureService capture) : IIpcMethodHandler
{
    public string Method => IpcMethods.StopCapture;

    public Task<JsonElement?> HandleAsync(JsonElement? parameters, CancellationToken ct)
    {
        var request = IpcParams.Parse<StopCaptureRequest>(parameters, Method);
        var stopped = capture.Stop(request.SessionId);

        return Task.FromResult<JsonElement?>(
            JsonSerializer.SerializeToElement(new { stopped }, IpcChannel.Json));
    }
}
