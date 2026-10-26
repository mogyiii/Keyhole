namespace Keyhole.Core.Capture;

public enum CaptureMode
{
    /// <summary>
    /// The target process writes TLS secrets itself, because Keyhole set SSLKEYLOGFILE
    /// in its environment at launch.
    /// </summary>
    Keylog,

    /// <summary>Reserved for a future intercepting proxy. Not implemented.</summary>
    Proxy,
}

/// <summary>
/// One capture of an application's TLS secrets.
///
/// The environment variable is set only on the process Keyhole launches, so nothing else
/// on the machine starts writing secrets — which is exactly the problem with setting
/// SSLKEYLOGFILE globally and remembering to turn it off.
/// </summary>
public sealed record CaptureSession
{
    public long Id { get; init; }

    public required string ExecutablePath { get; init; }

    /// <summary>PID of the launched process, or null once it has exited.</summary>
    public int? ProcessId { get; init; }

    public CaptureMode Mode { get; init; } = CaptureMode.Keylog;

    /// <summary>Folder holding this session's files.</summary>
    public required string Directory { get; init; }

    /// <summary>Where the target process writes its TLS secrets.</summary>
    public required string KeylogFile { get; init; }

    public required DateTimeOffset StartedUtc { get; init; }

    public DateTimeOffset? StoppedUtc { get; init; }

    public bool IsRunning => StoppedUtc is null;

    public string DisplayName => Path.GetFileName(ExecutablePath);
}

public sealed class CaptureException(string message, Exception? inner = null)
    : Exception(message, inner);
