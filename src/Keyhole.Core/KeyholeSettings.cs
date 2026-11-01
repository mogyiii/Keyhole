using System.Text.Json;
using System.Text.Json.Serialization;

namespace Keyhole.Core;

/// <summary>
/// User-adjustable settings, stored as JSON next to the database.
///
/// Deliberately small: every entry here is something a person has a real reason to change.
/// Anything Keyhole can decide correctly on its own stays a constant in the code.
/// </summary>
public sealed record KeyholeSettings
{
    /// <summary>How long flow history is kept before pruning.</summary>
    public int RetentionDays { get; init; } = 30;

    /// <summary>Close to the tray instead of exiting, so monitoring stays visible.</summary>
    public bool MinimiseToTray { get; init; } = true;

    /// <summary>Start the UI when the user signs in. The service starts independently.</summary>
    public bool StartWithWindows { get; init; }

    /// <summary>Resolve remote addresses to hostnames.</summary>
    public bool ResolveHostnames { get; init; } = true;

    /// <summary>"auto", "light" or "dark".</summary>
    public string Theme { get; init; } = "auto";

    /// <summary>
    /// How large one capture session's packet file may grow, in megabytes.
    ///
    /// A browser session produces hundreds of megabytes in minutes, so this needs a
    /// ceiling. Reaching it stops the recording and says so; the session itself keeps
    /// running and keeps collecting TLS keys.
    /// </summary>
    public int MaxPcapMegabytes { get; init; } = 512;

    [JsonIgnore]
    public TimeSpan Retention => TimeSpan.FromDays(Math.Clamp(RetentionDays, 1, 3650));

    /// <summary>
    /// The capture ceiling in bytes. Clamped rather than validated: a nonsensical value in
    /// a hand-edited settings file should land on something workable, not stop captures.
    /// </summary>
    [JsonIgnore]
    public long MaxPcapBytes => Math.Clamp(MaxPcapMegabytes, 1, 1024 * 1024) * 1024L * 1024L;
}

/// <summary>Loads and saves <see cref="KeyholeSettings"/>, tolerating a missing or broken file.</summary>
public static class SettingsStore
{
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
    };

    public static string FilePath => Path.Combine(KeyholePaths.DataRoot, "settings.json");

    /// <summary>
    /// Reads settings, falling back to defaults. A corrupt file must not stop Keyhole
    /// starting — the defaults are all usable.
    /// </summary>
    public static KeyholeSettings Load()
    {
        try
        {
            if (!File.Exists(FilePath))
            {
                return new KeyholeSettings();
            }

            return JsonSerializer.Deserialize<KeyholeSettings>(File.ReadAllText(FilePath), Json)
                   ?? new KeyholeSettings();
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            return new KeyholeSettings();
        }
    }

    public static void Save(KeyholeSettings settings)
    {
        KeyholePaths.EnsureCreated();

        // Write to a temporary file and move it into place, so a crash mid-write cannot
        // leave a half-written settings file that then fails to parse.
        var temp = FilePath + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(settings, Json));
        File.Move(temp, FilePath, overwrite: true);
    }
}
