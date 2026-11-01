using System.Diagnostics;
using Keyhole.Core.Capture.Recording;
using Keyhole.Core.Monitoring;
using Keyhole.Core.Storage;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Keyhole.Core.Capture;

/// <summary>
/// Launches an application with TLS key logging enabled for that process alone, and
/// records its packets alongside.
///
/// The key logging is the answer to the workflow Keyhole was built to replace: setting
/// SSLKEYLOGFILE as a user- or machine-wide variable, remembering to unset it, and
/// restarting the app twice. Here the variable exists only inside the launched process's
/// environment block, so nothing else on the machine ever writes secrets and there is
/// nothing to turn off.
///
/// Packet recording closes the other half of the loop. Keyhole owns both the traffic and
/// the keys, so the session's capture file carries its own secrets and needs no second
/// tool to be readable. Recording is optional throughout: it needs Npcap, which Keyhole
/// does not ship, and a session without it still logs keys exactly as before.
///
/// Works with anything built on NSS or OpenSSL — Chrome, Firefox, Electron, Node, curl.
/// Applications using Windows' own Schannel, which includes most native .NET software,
/// ignore the variable; see <see cref="SupportsKeylog"/>.
/// </summary>
public sealed class CaptureService(
    SessionRepository sessions,
    ILogger<CaptureService>? logger = null,
    string? captureRoot = null,
    IPacketDeviceFactory? packetDevices = null,
    ISocketTableReader? sockets = null,
    IProcessTreeReader? processTree = null,
    ILoggerFactory? loggerFactory = null)
{
    private readonly ILogger _logger = logger ?? NullLogger<CaptureService>.Instance;

    /// <summary>
    /// Where session folders are created. Overridable so tests do not litter the real
    /// machine-wide capture folder with throwaway sessions.
    /// </summary>
    private readonly string _captureRoot = captureRoot ?? KeyholePaths.CaptureRoot;

    /// <summary>The variable NSS and OpenSSL read to decide where to write TLS secrets.</summary>
    public const string KeylogVariable = "SSLKEYLOGFILE";

    /// <summary>The capture file inside a session folder.</summary>
    public const string PcapFileName = "capture.pcapng";

    private readonly Dictionary<long, Process> _running = [];
    private readonly Dictionary<long, PacketRecording> _recordings = [];

    /// <summary>
    /// Why each session is not recording packets, kept after the recording itself is gone.
    ///
    /// Needed because the UI shows a note for finished sessions too, and "Npcap is not
    /// installed" is precisely what a user needs to see against a finished keylog-only
    /// capture. Reading it from the live recording would make the explanation vanish the
    /// moment the session ended.
    /// </summary>
    private readonly Dictionary<long, string> _recordingIssues = [];

    private readonly Lock _gate = new();

    /// <summary>
    /// How large a session's capture file may grow before recording stops.
    /// Settable so the UI's setting reaches it; the session keeps running either way.
    /// </summary>
    public long MaxPcapBytes { get; set; } = PacketRecording.DefaultMaxBytes;

    /// <summary>
    /// Whether packet recording is wired up at all. False in the unit tests and anywhere
    /// Npcap's binding was not registered, in which case sessions are keylog-only.
    /// </summary>
    public bool CanRecordPackets => packetDevices is not null && sockets is not null;

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

        // Read once, before anything can dispose the Process. A short-lived program can
        // exit while this method is still running, and the exit handler below disposes the
        // object — after which reading Id throws. Capturing it here is what keeps starting
        // a capture of something that exits immediately from failing.
        var processId = process.Id;

        var session = sessions.Create(new CaptureSession
        {
            ExecutablePath = executablePath,
            ProcessId = processId,
            Mode = CaptureMode.Keylog,
            Directory = directory,
            KeylogFile = keylogFile,
            StartedUtc = startedUtc,
        });

        lock (_gate)
        {
            _running[session.Id] = process;
        }

        // Recording starts before the exit handler is wired, so that a process which has
        // already exited cannot have its recording torn down before it is registered.
        var recording = StartRecording(session.Id, directory, processId, executablePath);

        // Mark the session finished when the app closes, so the UI does not show a
        // capture as live long after the user quit the program.
        process.EnableRaisingEvents = true;
        process.Exited += (_, _) => OnProcessExited(session.Id);

        // A program that exited before the handler was attached never raises the event, so
        // the session would stay "running" forever. Checked after wiring, not before, so
        // the two paths cannot both miss it.
        //
        // Guarded because the handler may already have run on a pool thread and disposed
        // the Process; a session no longer in _running has been dealt with.
        if (StillRunning(session.Id) && HasExited(process))
        {
            OnProcessExited(session.Id);
        }

        _logger.LogInformation(
            "Capture {Id} started: {Path} (pid {Pid}), keys at {Keylog}, packets: {Packets}",
            session.Id, executablePath, processId, keylogFile,
            recording?.PcapngPath ?? recording?.UnavailableReason ?? "not configured");

        return session with { PcapFile = recording?.PcapngPath };
    }

    /// <summary>Whether this session's launched process has not yet been cleaned up.</summary>
    private bool StillRunning(long sessionId)
    {
        lock (_gate)
        {
            return _running.ContainsKey(sessionId);
        }
    }

    /// <summary>
    /// Whether the process has exited, tolerating a disposed object.
    ///
    /// A disposed Process means the exit handler got there first, which answers the
    /// question just as well as a true would.
    /// </summary>
    private static bool HasExited(Process process)
    {
        try
        {
            return process.HasExited;
        }
        catch (Exception ex) when (ex is InvalidOperationException or ObjectDisposedException)
        {
            return false;
        }
    }

    /// <summary>
    /// Begins recording this session's packets, or returns null when recording is not
    /// wired up at all.
    ///
    /// Never throws. A capture that cannot record packets is still a capture — the TLS
    /// keys are collected either way — so a missing Npcap, an unopenable adapter or an
    /// unwritable folder all degrade to a keylog-only session with a reason attached,
    /// rather than failing the launch the user just asked for.
    /// </summary>
    private PacketRecording? StartRecording(
        long sessionId, string directory, int processId, string executablePath)
    {
        if (packetDevices is null || sockets is null)
        {
            return null;
        }

        var tracker = new TargetPortTracker(
            sockets,
            processTree ?? new SingleProcessTree(),
            loggerFactory?.CreateLogger<TargetPortTracker>());

        var recording = PacketRecording.Start(
            packetDevices,
            tracker,
            Path.Combine(directory, PcapFileName),
            processId,
            executablePath,
            MaxPcapBytes,
            loggerFactory?.CreateLogger<PacketRecording>());

        lock (_gate)
        {
            _recordings[sessionId] = recording;

            if (recording.UnavailableReason is { } unavailable)
            {
                // Recorded now rather than on stop: a recording that never started has
                // nothing to report later, and this is the reason a user most needs.
                _recordingIssues[sessionId] = unavailable;
            }
        }

        // Stored only once there is a file to point at, so the UI never offers to open a
        // capture that was never created.
        if (recording.PcapngPath is { } path)
        {
            sessions.SetPcapFile(sessionId, path);
        }
        else if (recording.UnavailableReason is { } reason)
        {
            _logger.LogInformation(
                "Capture {Id} is keylog-only: {Reason}", sessionId, reason);
        }

        return recording;
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

        var summary = StopRecording(sessionId, session);

        sessions.MarkStopped(sessionId, DateTimeOffset.UtcNow);

        _logger.LogInformation(
            "Capture {Id} stopped. {Packets} packets of {Considered} seen, {Bytes} bytes, " +
            "secrets embedded: {Embedded}.",
            sessionId,
            summary?.Packets ?? 0,
            summary?.PacketsConsidered ?? 0,
            summary?.Bytes ?? 0,
            summary?.SecretsEmbedded ?? false);

        return true;
    }

    /// <summary>
    /// Ends this session's packet recording and finishes its file, embedding whatever TLS
    /// secrets the application wrote so the capture decrypts on its own.
    /// </summary>
    private RecordingSummary? StopRecording(long sessionId, CaptureSession session)
    {
        PacketRecording? recording;

        lock (_gate)
        {
            if (!_recordings.Remove(sessionId, out recording))
            {
                return null;
            }
        }

        try
        {
            var summary = recording.Stop(ReadKeylog(session.KeylogFile));

            // A recording that hit its ceiling, or whose secrets could not be embedded,
            // produced a capture that is less than the user asked for. Remembered so the
            // finished session can still say so.
            var issue = summary.CapReached
                ? $"recording stopped at the {MaxPcapBytes / (1024 * 1024)} MB limit"
                : summary.Detail;

            if (issue is not null)
            {
                lock (_gate)
                {
                    _recordingIssues[sessionId] = issue;
                }
            }

            return summary;
        }
        catch (Exception ex)
        {
            // Stopping must not fail the stop: the session is over either way, and a
            // throw here would leave it marked as running forever.
            _logger.LogError(ex, "Capture {Id}'s recording did not stop cleanly.", sessionId);
            return null;
        }
    }

    /// <summary>
    /// The secrets the target process wrote, or null when it wrote none.
    ///
    /// Read with sharing because the application may still have the file open — it is the
    /// writer, and it is deliberately left running when a capture stops.
    /// </summary>
    private string? ReadKeylog(string keylogFile)
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
            _logger.LogWarning(ex, "Could not read the keylog at {Path}.", keylogFile);
            return null;
        }
    }

    public IReadOnlyList<CaptureSession> ListSessions() => sessions.ListAll();

    /// <summary>
    /// Why this session is not recording packets, or null when it is (or never had a
    /// recording to begin with).
    /// </summary>
    public string? GetRecordingIssue(long sessionId)
    {
        lock (_gate)
        {
            if (_recordings.TryGetValue(sessionId, out var recording))
            {
                if (recording.UnavailableReason is { } reason)
                {
                    return reason;
                }

                if (!recording.IsRecording)
                {
                    return "recording stopped at the size limit";
                }

                return null;
            }

            // The recording is over. Whatever was wrong with it is still worth saying.
            return _recordingIssues.GetValueOrDefault(sessionId);
        }
    }

    /// <summary>Size of a session's capture file, or 0 when there is none yet.</summary>
    public long GetPcapSize(string? pcapFile)
    {
        if (string.IsNullOrEmpty(pcapFile))
        {
            return 0;
        }

        try
        {
            return File.Exists(pcapFile) ? new FileInfo(pcapFile).Length : 0;
        }
        catch (IOException)
        {
            return 0;
        }
    }

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
            // The recording has to be finished here too, not only on an explicit stop:
            // when the user simply closes the browser, this is the one place that runs,
            // and without it the capture file would never get its secrets — nor be
            // closed, leaving the adapters open for the life of the service.
            var session = sessions.FindById(sessionId);
            if (session is not null)
            {
                StopRecording(sessionId, session);
            }

            sessions.MarkStopped(sessionId, DateTimeOffset.UtcNow);
            _logger.LogInformation("Capture {Id} ended: the application exited.", sessionId);
        }
        catch (Exception ex)
        {
            // Raised on a pool thread; an exception here would take the process down.
            _logger.LogError(ex, "Could not mark capture {Id} as stopped.", sessionId);
        }
    }

    /// <summary>
    /// Stops every running recording. Called when the service shuts down, so a capture
    /// file is closed and carries its secrets rather than being left mid-write.
    /// </summary>
    public void StopAllRecordings()
    {
        List<long> ids;

        lock (_gate)
        {
            ids = [.. _recordings.Keys];
        }

        foreach (var id in ids)
        {
            var session = sessions.FindById(id);
            if (session is not null)
            {
                StopRecording(id, session);
            }
        }
    }
}

/// <summary>
/// The fallback process scope: the launched process alone.
///
/// Only used when no real tree reader was supplied, which means the unit tests. It is
/// deliberately not the production default — a browser's traffic lives in its children,
/// so scoping a real capture this way would record almost nothing.
/// </summary>
internal sealed class SingleProcessTree : IProcessTreeReader
{
    public HashSet<int> DescendantsOf(int rootProcessId, string? executablePath) =>
        [rootProcessId];
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
