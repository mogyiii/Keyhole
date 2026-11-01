using System.Globalization;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace Keyhole.Tests;

/// <summary>
/// The two languages, checked against each other and against the markup that uses them.
///
/// A missing translation is the failure mode worth guarding: it does not throw, it renders
/// a key or an English sentence in a Hungarian window, and it survives review because
/// nobody reads every label every time. These tests read the resx files and the XAML as
/// files rather than through the resource manager, so they fail at build time with the
/// offending key named.
/// </summary>
public class LocalizationTests
{
    private static string RepositoryRoot
    {
        get
        {
            // Walk up from the test assembly to the directory holding the solution.
            var directory = new DirectoryInfo(AppContext.BaseDirectory);

            while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Keyhole.slnx")))
            {
                directory = directory.Parent;
            }

            Assert.NotNull(directory);
            return directory!.FullName;
        }
    }

    private static string LocalizationDirectory =>
        Path.Combine(RepositoryRoot, "src", "Keyhole.App", "Localization");

    private static string MainWindowXaml =>
        Path.Combine(RepositoryRoot, "src", "Keyhole.App", "Views", "MainWindow.axaml");

    /// <summary>Resource keys and values from one resx file.</summary>
    private static Dictionary<string, string> ReadResx(string fileName)
    {
        var document = XDocument.Load(Path.Combine(LocalizationDirectory, fileName));

        return document.Root!
            .Elements("data")
            .Where(e => e.Attribute("name") is not null)
            .ToDictionary(
                e => e.Attribute("name")!.Value,
                e => e.Element("value")?.Value ?? "",
                StringComparer.Ordinal);
    }

    [Fact]
    public void Both_languages_define_exactly_the_same_keys()
    {
        var english = ReadResx("Strings.resx");
        var hungarian = ReadResx("Strings.hu.resx");

        Assert.NotEmpty(english);

        var untranslated = english.Keys.Except(hungarian.Keys).Order().ToList();
        var orphaned = hungarian.Keys.Except(english.Keys).Order().ToList();

        // Named individually, because "the files differ" sends the reader looking.
        Assert.True(
            untranslated.Count == 0,
            $"Missing Hungarian translations: {string.Join(", ", untranslated)}");

        // An orphan is a key that was renamed or removed on one side only; it is dead
        // weight at best and a sign the rename was half-done at worst.
        Assert.True(
            orphaned.Count == 0,
            $"Hungarian keys with no English original: {string.Join(", ", orphaned)}");
    }

    [Fact]
    public void No_string_is_left_empty()
    {
        foreach (var file in (string[])["Strings.resx", "Strings.hu.resx"])
        {
            var blank = ReadResx(file)
                .Where(pair => string.IsNullOrWhiteSpace(pair.Value))
                .Select(pair => pair.Key)
                .Order()
                .ToList();

            // An empty value renders as a blank label, which looks like a layout bug
            // rather than a missing string.
            Assert.True(blank.Count == 0, $"{file} has empty values: {string.Join(", ", blank)}");
        }
    }

    [Fact]
    public void Every_key_the_markup_asks_for_exists()
    {
        var english = ReadResx("Strings.resx");
        var xaml = File.ReadAllText(MainWindowXaml);

        // Matches the markup extension's positional form: {l:Translate SomeKey}
        var used = Regex.Matches(xaml, @"\{l:Translate\s+([A-Za-z0-9_]+)")
            .Select(m => m.Groups[1].Value)
            .Distinct(StringComparer.Ordinal)
            .Order()
            .ToList();

        var undefined = used.Except(english.Keys).ToList();

        Assert.True(
            undefined.Count == 0,
            $"The window asks for keys no resource defines: {string.Join(", ", undefined)}");
    }

    [Fact]
    public void Every_defined_key_is_actually_used()
    {
        var english = ReadResx("Strings.resx");
        var xaml = File.ReadAllText(MainWindowXaml);

        // The view model composes some strings itself, so a key may be referenced from C#
        // rather than from markup. Both are searched.
        var code = Directory
            .EnumerateFiles(
                Path.Combine(RepositoryRoot, "src", "Keyhole.App"),
                "*.cs",
                SearchOption.AllDirectories)
            .Where(path => !path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}"))
            .Select(File.ReadAllText)
            .ToList();

        var unused = english.Keys
            .Where(key => !xaml.Contains(key, StringComparison.Ordinal))
            .Where(key => !code.Any(text => text.Contains($"\"{key}\"", StringComparison.Ordinal)))
            .Order()
            .ToList();

        // Dead strings are not harmful, but they are translated twice and reviewed
        // forever, so they are worth knowing about.
        Assert.True(unused.Count == 0, $"Unused resource keys: {string.Join(", ", unused)}");
    }

    [Theory]
    [InlineData("en", "Language")]
    [InlineData("hu", "Nyelv")]
    public void A_key_resolves_to_the_right_language(string culture, string expected)
    {
        // Through the resource manager rather than the files, so this also proves the
        // resources are embedded under the name the lookup uses and that the Hungarian
        // satellite assembly is produced and found.
        var resources = new System.Resources.ResourceManager(
            "Keyhole.App.Localization.Strings",
            typeof(Keyhole.App.Localization.Loc).Assembly);

        Assert.Equal(expected, resources.GetString("SettingsLanguage", CultureInfo.GetCultureInfo(culture)));
    }

    [Fact]
    public void Switching_language_announces_that_every_string_changed()
    {
        // This one notification is what refreshes the whole window. Raising it per key
        // would mean one subscription per string; the empty name is the convention for
        // "everything changed", and without it a language switch would need a restart.
        var loc = Keyhole.App.Localization.Loc.Current;
        var original = loc.Culture;

        var announced = new List<string?>();
        loc.PropertyChanged += (_, e) => announced.Add(e.PropertyName);

        try
        {
            loc.SetCulture(CultureInfo.GetCultureInfo(
                original.TwoLetterISOLanguageName == "hu" ? "en" : "hu"));

            Assert.Contains("", announced);

            // A second call with the same culture must say nothing, or every refresh
            // would rebuild the lists for no reason.
            announced.Clear();
            loc.SetCulture(loc.Culture);
            Assert.Empty(announced);
        }
        finally
        {
            loc.SetCulture(original);
        }
    }

    [Fact]
    public void A_missing_key_renders_as_the_key_itself()
    {
        // Rather than blank. A label reading "SomeMissingKey" is obviously broken; an
        // empty label looks like a layout problem and can survive review.
        var loc = Keyhole.App.Localization.Loc.Current;

        const string absent = "ThisKeyDoesNotExist";

        Assert.Equal(absent, loc[absent]);
        Assert.Contains(absent, loc.MissingKeys);
    }

    [Fact]
    public void The_markup_extension_binds_to_the_shared_strings()
    {
        // The source is the singleton rather than the data context, which is the detail
        // that makes the same markup work on a DataGrid column header — those sit outside
        // the visual tree and have no data context to resolve against.
        var binding = Assert.IsType<Avalonia.Data.Binding>(
            new Keyhole.App.Localization.TranslateExtension("SettingsLanguage")
                .ProvideValue(null!));

        Assert.Same(Keyhole.App.Localization.Loc.Current, binding.Source);
        Assert.Equal("[SettingsLanguage]", binding.Path);
        Assert.Equal(Avalonia.Data.BindingMode.OneWay, binding.Mode);
    }

    [Theory]
    // An explicit choice is honoured whatever the system is set to.
    [InlineData("hu", "hu")]
    [InlineData("en", "en")]
    // Anything else follows the system, but falls back to English rather than to the
    // system culture verbatim: a German system has no German resources and would
    // otherwise be shown raw keys.
    [InlineData("auto", null)]
    [InlineData(null, null)]
    [InlineData("de", null)]
    public void The_language_setting_resolves_sensibly(string? setting, string? expected)
    {
        var resolved = Keyhole.App.Localization.AppLanguage.Resolve(setting);

        if (expected is not null)
        {
            Assert.Equal(expected, resolved.TwoLetterISOLanguageName);
        }
        else
        {
            // Whatever the machine running the tests is set to, the result must be a
            // language Keyhole actually has resources for.
            Assert.Contains(resolved.TwoLetterISOLanguageName, (string[])["en", "hu"]);
        }
    }
}
