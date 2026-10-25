namespace Keyhole.Core;

/// <summary>
/// Single source of truth for where Keyhole keeps state on disk.
/// The service runs as LocalSystem, so it must not use per-user folders: both halves
/// resolve the same machine-wide ProgramData root.
/// </summary>
public static class KeyholePaths
{
    public static string DataRoot { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Keyhole");

    public static string DatabaseFile => Path.Combine(DataRoot, "keyhole.sqlite");

    public static string LogDirectory => Path.Combine(DataRoot, "logs");

    /// <summary>Capture sessions: one subfolder per session holding its pcap and TLS keylog.</summary>
    public static string CaptureRoot => Path.Combine(DataRoot, "captures");

    /// <summary>Creates every directory Keyhole writes to. Safe to call repeatedly.</summary>
    public static void EnsureCreated()
    {
        Directory.CreateDirectory(DataRoot);
        Directory.CreateDirectory(LogDirectory);
        Directory.CreateDirectory(CaptureRoot);
    }
}
