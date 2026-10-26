using Keyhole.Native;
using Xunit.Abstractions;

namespace Keyhole.Tests;

public class IconExtractorTests(ITestOutputHelper output)
{
    private readonly IconExtractor _extractor = new();

    [Fact]
    public void Extracts_an_icon_from_a_system_executable()
    {
        var path = Path.Combine(Environment.SystemDirectory, "notepad.exe");
        if (!File.Exists(path))
        {
            path = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        }

        var icon = _extractor.TryGet(path);

        Assert.NotNull(icon);
        output.WriteLine($"{Path.GetFileName(path)}: {icon.Width}x{icon.Height}, {icon.Bgra.Length} bytes");

        Assert.True(icon.Width > 0);
        Assert.True(icon.Height > 0);
        Assert.Equal(icon.Width * icon.Height * 4, icon.Bgra.Length);
    }

    [Fact]
    public void Extracted_pixels_are_not_blank()
    {
        var path = Path.Combine(Environment.SystemDirectory, "cmd.exe");

        var icon = _extractor.TryGet(path);
        Assert.NotNull(icon);

        // A silently failing GetDIBits returns a zero-filled buffer, which would render
        // as an empty square rather than an error.
        var opaque = 0;
        var coloured = 0;
        for (var i = 0; i < icon.Bgra.Length; i += 4)
        {
            if (icon.Bgra[i + 3] != 0)
            {
                opaque++;
            }

            if (icon.Bgra[i] != 0 || icon.Bgra[i + 1] != 0 || icon.Bgra[i + 2] != 0)
            {
                coloured++;
            }
        }

        output.WriteLine($"{opaque} opaque and {coloured} coloured pixels of {icon.Bgra.Length / 4}");

        Assert.True(opaque > 0, "Every pixel was fully transparent.");
        Assert.True(coloured > 0, "Every pixel was black.");
    }

    [Fact]
    public void Missing_file_still_yields_a_generic_icon_or_null()
    {
        // USEFILEATTRIBUTES means the shell works from the path string, so an
        // inaccessible file still produces its file-type icon rather than throwing.
        var icon = _extractor.TryGet(@"C:\does\not\exist\anywhere.exe");

        output.WriteLine(icon is null ? "null" : $"{icon.Width}x{icon.Height}");

        if (icon is not null)
        {
            Assert.Equal(icon.Width * icon.Height * 4, icon.Bgra.Length);
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Blank_path_returns_null(string? path)
    {
        // Processes with no readable path reach here on every refresh.
        Assert.Null(_extractor.TryGet(path));
    }

    [Fact]
    public void Repeated_lookups_are_served_from_cache()
    {
        var path = Path.Combine(Environment.SystemDirectory, "cmd.exe");

        var first = _extractor.TryGet(path);
        var second = _extractor.TryGet(path);

        // Reference equality proves the second call did not go back to the shell.
        Assert.Same(first, second);
    }

    [Fact]
    public void Different_executables_get_different_icons()
    {
        var cmd = _extractor.TryGet(Path.Combine(Environment.SystemDirectory, "cmd.exe"));
        var explorer = _extractor.TryGet(Path.Combine(Environment.SystemDirectory, "..", "explorer.exe"));

        if (cmd is null || explorer is null)
        {
            output.WriteLine("One of the icons was unavailable; nothing to compare.");
            return;
        }

        // A caching bug keyed on something constant would hand back the same pixels
        // for every application in the list.
        Assert.False(cmd.Bgra.AsSpan().SequenceEqual(explorer.Bgra));
    }
}
