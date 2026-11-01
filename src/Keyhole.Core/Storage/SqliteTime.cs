using System.Globalization;

namespace Keyhole.Core.Storage;

/// <summary>
/// Reads the timestamps stored in SQLite.
///
/// Only reading needs help. Writing uses <c>ToString("O")</c>, the round-trip format,
/// which ignores the culture by specification — but reading used a plain
/// <c>DateTimeOffset.Parse</c>, which does not. That was harmless only while the
/// application ran with globalization switched off; the moment it was turned on for the
/// Hungarian interface, every stored timestamp began being parsed under whatever locale
/// the machine happens to use.
///
/// It would most likely have kept working, because Parse recognises ISO-8601 under
/// essentially every culture. "Most likely" is not a good property for the code that
/// reads back a user's history, so the format is stated rather than inferred.
/// </summary>
internal static class SqliteTime
{
    /// <summary>The format every stored timestamp is written in.</summary>
    private const string RoundTrip = "O";

    /// <summary>
    /// Parses a stored timestamp.
    ///
    /// Exact first, because that is what the writer produces. The looser fallback exists
    /// for rows an older build may have written differently: losing a user's history to a
    /// format quibble would be worse than accepting a wider parse, and both paths are
    /// pinned to the invariant culture either way.
    /// </summary>
    public static DateTimeOffset Read(string stored) =>
        DateTimeOffset.TryParseExact(
            stored, RoundTrip, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind,
            out var exact)
            ? exact
            : DateTimeOffset.Parse(
                stored, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
}
