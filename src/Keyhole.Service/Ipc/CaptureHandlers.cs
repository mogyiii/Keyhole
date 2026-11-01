using System.Text.Json;
using Keyhole.Core.Capture;
using Keyhole.Core.Capture.Decode;
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
        PcapFile = session.PcapFile,
        PcapBytes = capture.GetPcapSize(session.PcapFile),
        RecordingIssue = capture.GetRecordingIssue(session.Id),
    };
}

/// <summary>
/// Answers <see cref="IpcMethods.DecodeCapture"/> by reading a session's capture file and
/// recovering the HTTP exchanges inside it.
///
/// Deliberately on demand rather than part of the session list: decoding reads every
/// packet, and a 500 MB capture takes long enough that doing it on every UI refresh would
/// make the Capture tab unusable.
/// </summary>
public sealed class DecodeCaptureHandler(CaptureService capture, CaptureDecoder decoder)
    : IIpcMethodHandler
{
    public string Method => IpcMethods.DecodeCapture;

    public Task<JsonElement?> HandleAsync(JsonElement? parameters, CancellationToken ct)
    {
        var request = IpcParams.Parse<DecodeCaptureRequest>(parameters, Method);

        var session = capture.ListSessions().FirstOrDefault(s => s.Id == request.SessionId);
        if (session is null)
        {
            throw new IpcInvalidParamsException($"There is no capture session {request.SessionId}.");
        }

        if (session.PcapFile is null)
        {
            // Not an error: a session without Npcap collects TLS keys and no packets, and
            // there is simply nothing to decode.
            return Task.FromResult<JsonElement?>(JsonSerializer.SerializeToElement(
                new DecodeCaptureResponse
                {
                    Summary = "This session recorded no packets, so there is nothing to decode. " +
                              "Packet recording needs Npcap.",
                    Failure = "no packet capture for this session",
                },
                IpcChannel.Json));
        }

        // A running session has not had its secrets written into the capture yet — that
        // happens when it stops — so the keylog on disk is passed as the fallback.
        var keylog = session.IsRunning ? ReadKeylog(session.KeylogFile) : null;

        var result = decoder.Decode(session.PcapFile, keylog);

        // Bounded because the answer has to fit one IPC frame, and the frame limit is
        // 4 MB. A browser session can hold thousands of requests, and headers are the
        // bulk of each one — so an uncapped response would be refused by the framing
        // layer and reach the user as a protocol error rather than as a result.
        var truncated = result.Exchanges.Count > MaxExchanges;

        var exchanges = result.Exchanges
            .Take(MaxExchanges)
            .Select(ToSummary)
            .ToList();

        var summary = truncated
            ? $"{result.Summary} Showing the first {MaxExchanges} of " +
              $"{result.Exchanges.Count} requests."
            : result.Summary;

        return Task.FromResult<JsonElement?>(JsonSerializer.SerializeToElement(
            new DecodeCaptureResponse
            {
                Exchanges = exchanges,
                Summary = summary,
                Conversations = result.Conversations,
                Decrypted = result.Decrypted,
                HandshakeMissing = result.HandshakeMissing,
                DecryptionFailed = result.DecryptionFailed,
                Failure = result.Failure,
            },
            IpcChannel.Json));
    }

    /// <summary>
    /// How many exchanges one answer may carry. Chosen to stay well inside the IPC frame
    /// limit even when every request has a full set of headers.
    /// </summary>
    private const int MaxExchanges = 1000;

    /// <summary>
    /// Headers kept per direction. A handful of requests carry dozens of cookies, and a
    /// cap here costs almost nothing while removing the worst case from the frame budget.
    /// </summary>
    private const int MaxHeadersPerDirection = 64;

    private static ExchangeSummary ToSummary(DecodedExchange exchange) => new()
    {
        Protocol = exchange.Protocol,
        Method = exchange.Method,
        Url = exchange.Url,
        StatusCode = exchange.StatusCode,
        ContentType = exchange.ContentType,
        RequestBytes = exchange.RequestBodyBytes,
        ResponseBytes = exchange.ResponseBodyBytes,
        RequestedUtc = exchange.RequestedUtc,
        DurationMs = exchange.Duration?.TotalMilliseconds,
        Incomplete = exchange.Incomplete,
        RequestHeaders =
            [.. exchange.RequestHeaders.Take(MaxHeadersPerDirection)
                .Select(h => new HeaderPair(h.Name, Truncate(h.Value)))],
        ResponseHeaders =
            [.. exchange.ResponseHeaders.Take(MaxHeadersPerDirection)
                .Select(h => new HeaderPair(h.Name, Truncate(h.Value)))],
    };

    /// <summary>
    /// Caps one header value's length. A Set-Cookie or a CSP can run to several kilobytes,
    /// and a tooltip shows none of that anyway.
    /// </summary>
    private static string Truncate(string value) =>
        value.Length <= 512 ? value : value[..512] + "...";

    /// <summary>
    /// The keylog as it stands, shared-read because the captured application still has it
    /// open — it is the writer, and a stopped capture leaves it running.
    /// </summary>
    private static string? ReadKeylog(string keylogFile)
    {
        try
        {
            if (!File.Exists(keylogFile))
            {
                return null;
            }

            using var stream = new FileStream(
                keylogFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var reader = new StreamReader(stream);

            return reader.ReadToEnd();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
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
