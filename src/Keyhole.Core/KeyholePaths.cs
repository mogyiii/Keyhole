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

    /// <summary>
    /// Where the user drops MaxMind MMDB files for country and ASN lookups.
    ///
    /// A folder rather than a configured path: the databases come as two separate files
    /// and are replaced wholesale when updated, so "put them here" is less to get wrong
    /// than two settings to keep in step. Keyhole never writes here — the files are the
    /// user's, under MaxMind's licence, and are not shipped.
    /// </summary>
    public static string GeoIpDirectory => Path.Combine(DataRoot, "geoip");

    /// <summary>Creates every directory Keyhole writes to. Safe to call repeatedly.</summary>
    public static void EnsureCreated()
    {
        Directory.CreateDirectory(DataRoot);
        Directory.CreateDirectory(LogDirectory);
        Directory.CreateDirectory(CaptureRoot);

        // Created empty so there is somewhere obvious to put the files, and so the UI can
        // point at a path that exists.
        Directory.CreateDirectory(GeoIpDirectory);
    }
}
