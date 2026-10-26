using System.Diagnostics;
using Keyhole.Core.Storage;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Keyhole.Core.Capture;

/// <summary>
/// Launches an application with TLS key logging enabled for that process alone.
///
/// This is the answer to the workflow Keyhole was built to replace: setting SSLKEYLOGFILE
/// as a user- or machine-wide variable, remembering to unset it, and restarting the app
/// twice. Here the variable exists only inside the launched process's environment block,
/// so nothing else on the machine ever writes secrets and there is nothing to turn off.
///
/// Works with anything built on NSS or OpenSSL — Chrome, Firefox, Electron, Node, curl.
/// Applications using Windows' own Schannel, which includes most native .NET software,
/// ignore the variable; see <see cref="SupportsKeylog"/>.
/// </summary>
public sealed class CaptureService(
    SessionRepository sessions,
    ILogger<CaptureService>? logger = null,
    string? captureRoot = null)
{
    private readonly ILogger _logger = logger ?? NullLogger<CaptureService>.Instance;

    /// <summary>
    /// Where session folders are created. Overridable so tests do not litter the real
    /// machine-wide capture folder with throwaway sessions.
    /// </summary>
    private readonly string _captureRoot = captureRoot ?? KeyholePaths.CaptureRoot;

    /// <summary>The variable NSS and OpenSSL read to decide where to write TLS secrets.</summary>
    public const string KeylogVariable = "SSLKEYLOGFILE";

    private readonly Dictionary<long, Process> _running = [];
    private readonly Lock _gate = new();

    /// <summary>
    /// Starts <paramref name="executablePath"/> with key logging enabled.
    /// </summary>
    /// <param name="arguments">Command line passed through to the application.</param>
    public CaptureSession Start(string executablePath, string? arguments = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);

        if (!File.Exists(executablePath))
        {
            throw new CaptureException($"No executable at '{executablePath}'.");
        }

        var startedUtc = DateTimeOffset.UtcNow;
        var directory = CreateSessionDirectory(_captureRoot, executablePath, startedUtc);
        var keylogFile = Path.Combine(directory, "sslkeys.log");

        var startInfo = new ProcessStartInfo
        {
            FileName = executablePath,
            // Child processes inherit the environment, which matters: a browser's network
            // work happens in children, not in the launcher process.
            UseShellExecute = false,
            WorkingDirectory = Path.GetDirectoryName(executablePath) ?? Environment.CurrentDirectory,
        };

        if (!string.IsNullOrWhiteSpace(arguments))
        {
            startInfo.Arguments = arguments;
        }

        startInfo.Environment[KeylogVariable] = keylogFile;

        Process process;
        try
        {
            process = Process.Start(startInfo)
                      ?? throw new CaptureException($"Could not start '{executablePath}'.");
        }
        catch (Exception ex) when (ex is not CaptureException)
        {
            throw new CaptureException($"Could not start '{executablePath}': {ex.Message}", ex);
        }

        var session = sessions.Create(new CaptureSession
        {
            ExecutablePath = executablePath,
            ProcessId = process.Id,
            Mode = CaptureMode.Keylog,
            Directory = directory,
            KeylogFile = keylogFile,
            StartedUtc = startedUtc,
        });

        lock (_gate)
        {
            _running[session.Id] = process;
        }

        // Mark the session finished when the app closes, so the UI does not show a
        // capture as live long after the user quit the program.
        process.EnableRaisingEvents = true;
        process.Exited += (_, _) => OnProcessExited(session.Id);

        _logger.LogInformation(
            "Capture {Id} started: {Path} (pid {Pid}), keys at {Keylog}",
            session.Id, executablePath, process.Id, keylogFile);

        return session;
    }

    /// <summary>
    /// Stops a capture. The launched application is left running: the user started it to
    /// use it, and killing their browser to end a capture would be its own surprise.
    /// </summary>
    public bool Stop(long sessionId)
    {
        var session = sessions.FindById(sessionId);
        if (session is null || !session.IsRunning)
        {
            return false;
        }

        lock (_gate)
        {
            if (_running.Remove(sessionId, out var process))
            {
                process.Dispose();
            }
        }

        sessions.MarkStopped(sessionId, DateTimeOffset.UtcNow);
        _logger.LogInformation("Capture {Id} stopped.", sessionId);
        return true;
    }

    public IReadOnlyList<CaptureSession> ListSessions() => sessions.ListAll();

    /// <summary>Size of a session's keylog, or 0 when nothing has been written yet.</summary>
    public long GetKeylogSize(string keylogFile)
    {
        try
        {
            return File.Exists(keylogFile) ? new FileInfo(keylogFile).Length : 0;
        }
        catch (IOException)
        {
            return 0;
        }
    }

    /// <summary>
    /// Whether this executable is likely to honour the variable at all.
    ///
    /// A heuristic on purpose: there is no way to know before launching. It exists so the
    /// UI can warn up front rather than leaving the user staring at an empty keylog
    /// wondering what went wrong.
    /// </summary>
    public static KeylogSupport SupportsKeylog(string executablePath)
    {
        var name = Path.GetFileNameWithoutExtension(executablePath).ToLowerInvariant();

        // Windows system binaries use Schannel, which has no equivalent of this variable.
        // The bundled curl.exe is the trap here: it looks like the OpenSSL curl that does
        // honour SSLKEYLOGFILE, but `curl --version` on Windows reports Schannel, and a
        // capture of it silently produces an empty keylog.
        var systemRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (!string.IsNullOrEmpty(systemRoot) &&
            Path.GetFullPath(executablePath).StartsWith(systemRoot, StringComparison.OrdinalIgnoreCase))
        {
            return KeylogSupport.Unlikely;
        }

        string[] known =
        [
            "chrome", "chromium", "msedge", "brave", "opera", "vivaldi",
            "firefox", "librewolf", "waterfox", "thunderbird",
            "node", "electron", "curl", "python", "slack", "discord", "code",
        ];

        return known.Any(k => name.Contains(k, StringComparison.Ordinal))
            ? KeylogSupport.Likely
            : KeylogSupport.Unknown;
    }

    /// <summary>
    /// Creates a folder unique to this capture.
    ///
    /// The timestamp alone is not enough: two captures started inside the same second
    /// would land in one folder and share a keylog, mixing two applications' secrets
    /// into a file that decodes neither.
    /// </summary>
    private static string CreateSessionDirectory(
        string captureRoot, string executablePath, DateTimeOffset startedUtc)
    {
        var baseName = Path.Combine(
            captureRoot,
            $"{startedUtc:yyyyMMdd-HHmmss}-{Path.GetFileNameWithoutExtension(executablePath)}");

        var candidate = baseName;
        for (var suffix = 2; Directory.Exists(candidate); suffix++)
        {
            candidate = $"{baseName}-{suffix}";

            if (suffix > 1000)
            {
                throw new CaptureException(
                    $"Could not find an unused capture folder near '{baseName}'.");
            }
        }

        Directory.CreateDirectory(candidate);
        return candidate;
    }

    private void OnProcessExited(long sessionId)
    {
        lock (_gate)
        {
            if (_running.Remove(sessionId, out var process))
            {
                process.Dispose();
            }
        }

        try
        {
            sessions.MarkStopped(sessionId, DateTimeOffset.UtcNow);
            _logger.LogInformation("Capture {Id} ended: the application exited.", sessionId);
        }
        catch (Exception ex)
        {
            // Raised on a pool thread; an exception here would take the process down.
            _logger.LogError(ex, "Could not mark capture {Id} as stopped.", sessionId);
        }
    }
}

public enum KeylogSupport
{
    /// <summary>Built on NSS, BoringSSL or OpenSSL, which read the variable.</summary>
    Likely,

    /// <summary>Cannot be determined without launching it.</summary>
    Unknown,

    /// <summary>
    /// Known to use Schannel, which ignores the variable. Capturing will produce an
    /// empty keylog, so the UI should say so before the user waits on it.
    /// </summary>
    Unlikely,
}
