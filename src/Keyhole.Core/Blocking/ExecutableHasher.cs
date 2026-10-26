using System.Security.Cryptography;

namespace Keyhole.Core.Blocking;

/// <summary>
/// Hashes executables so a rule can tell whether the binary behind a blocked path is
/// still the one the user chose to block.
///
/// Only done when a rule is created, never during sampling: reading a large executable
/// is far too slow for a loop that runs every two seconds.
/// </summary>
public static class ExecutableHasher
{
    /// <summary>
    /// SHA-256 of the file, or null if it cannot be read. Null means "unknown", never
    /// "changed" — a rule must not be reported as tampered with because of a locked file.
    /// </summary>
    public static string? TryComputeSha256(string path)
    {
        try
        {
            using var stream = new FileStream(
                path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);

            return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
                                      or FileNotFoundException or DirectoryNotFoundException)
        {
            return null;
        }
    }

    /// <summary>
    /// Whether the file at <paramref name="path"/> still matches <paramref name="expected"/>.
    /// Unknown when either side cannot be established.
    /// </summary>
    public static HashVerdict Verify(string path, string? expected)
    {
        if (expected is null)
        {
            return HashVerdict.Unknown;
        }

        var actual = TryComputeSha256(path);
        if (actual is null)
        {
            return HashVerdict.Unknown;
        }

        return string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase)
            ? HashVerdict.Match
            : HashVerdict.Changed;
    }
}

public enum HashVerdict
{
    /// <summary>The file could not be hashed, or no hash was recorded.</summary>
    Unknown,

    /// <summary>Still the binary the rule was created for.</summary>
    Match,

    /// <summary>
    /// A different binary now sits at the blocked path. The rule still blocks the path,
    /// but the user should know what they are actually blocking has changed.
    /// </summary>
    Changed,
}
