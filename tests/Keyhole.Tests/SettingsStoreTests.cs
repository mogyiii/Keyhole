using System.Text.Json;
using Keyhole.Core;

namespace Keyhole.Tests;

public class KeyholeSettingsTests
{
    [Fact]
    public void Defaults_are_usable_without_a_settings_file()
    {
        var settings = new KeyholeSettings();

        Assert.Equal(30, settings.RetentionDays);
        Assert.True(settings.MinimiseToTray);
        Assert.True(settings.ResolveHostnames);
        Assert.False(settings.StartWithWindows);
        Assert.Equal("auto", settings.Theme);
    }

    [Theory]
    [InlineData(0, 1)]
    [InlineData(-5, 1)]
    [InlineData(30, 30)]
    [InlineData(100_000, 3650)]
    public void Retention_is_clamped_to_a_sane_range(int configured, int expectedDays)
    {
        // A zero or negative retention would delete history the moment it is written,
        // and an absurd one is almost certainly a typo.
        var settings = new KeyholeSettings { RetentionDays = configured };

        Assert.Equal(TimeSpan.FromDays(expectedDays), settings.Retention);
    }

    [Fact]
    public void Round_trips_through_json()
    {
        var original = new KeyholeSettings
        {
            RetentionDays = 7,
            MinimiseToTray = false,
            StartWithWindows = true,
            ResolveHostnames = false,
            Theme = "dark",
        };

        var options = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
        var restored = JsonSerializer.Deserialize<KeyholeSettings>(
            JsonSerializer.Serialize(original, options), options);

        Assert.Equal(original, restored);
    }

    [Fact]
    public void Unknown_fields_in_an_older_file_do_not_break_loading()
    {
        var json = """
            { "retentionDays": 14, "somethingRemovedLater": true, "theme": "light" }
            """;

        var options = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
        var settings = JsonSerializer.Deserialize<KeyholeSettings>(json, options);

        // A settings file written by a newer or older build must not stop Keyhole starting.
        Assert.NotNull(settings);
        Assert.Equal(14, settings.RetentionDays);
        Assert.Equal("light", settings.Theme);
        Assert.True(settings.MinimiseToTray);
    }
}
