using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Resources;

namespace Keyhole.App.Localization;

/// <summary>
/// The interface's strings, in the language currently in force.
///
/// An indexer rather than a generated property per string, for one reason that decides the
/// whole design: a DataGrid's columns are not part of the visual tree, so a plain
/// <c>{Binding}</c> on a column header has no data context to resolve against. Every
/// lookup therefore goes through this singleton as an explicit binding source — see
/// <see cref="TranslateExtension"/> — which works the same everywhere and needs no data
/// context at all.
///
/// Changing the language raises a change for every string at once, so the window updates
/// in place. A restart prompt would be the easier implementation and a worse one: the
/// setting is two clicks away from the thing it changes.
/// </summary>
public sealed class Loc : INotifyPropertyChanged
{
    public static Loc Current { get; } = new();

    private readonly ResourceManager _resources =
        new("Keyhole.App.Localization.Strings", typeof(Loc).Assembly);

    /// <summary>
    /// Keys asked for that no resource defines, remembered so a test can report them.
    ///
    /// A missing key renders as the key itself rather than blank: a screen reading
    /// "HostsTabHeader" is obviously broken, whereas an empty label looks like a layout
    /// problem and can survive review.
    /// </summary>
    private readonly HashSet<string> _missing = [];

    private Loc() => Culture = CultureInfo.CurrentUICulture;

    public CultureInfo Culture { get; private set; }

    public event PropertyChangedEventHandler? PropertyChanged;

    public string this[string key]
    {
        get
        {
            if (string.IsNullOrEmpty(key))
            {
                return "";
            }

            try
            {
                var value = _resources.GetString(key, Culture);

                if (value is not null)
                {
                    return value;
                }
            }
            catch (MissingManifestResourceException)
            {
                // The resources are embedded in this assembly, so this means a build
                // problem rather than anything a user can cause.
            }

            lock (_missing)
            {
                _missing.Add(key);
            }

            return key;
        }
    }

    /// <summary>Keys that were asked for and not found. Empty is the expected state.</summary>
    public IReadOnlyCollection<string> MissingKeys
    {
        get
        {
            lock (_missing)
            {
                return [.. _missing];
            }
        }
    }

    /// <summary>
    /// Switches language.
    ///
    /// The empty property name is the convention for "every property changed", which is
    /// what makes a single call refresh every bound string rather than needing one
    /// notification per key.
    /// </summary>
    public void SetCulture(CultureInfo culture)
    {
        if (Culture.Name == culture.Name)
        {
            return;
        }

        Culture = culture;

        // Also set the thread's culture so anything formatting a date or a number without
        // going through this class agrees with the interface.
        CultureInfo.CurrentUICulture = culture;

        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(""));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs("Item[]"));
    }
}

/// <summary>
/// The languages Keyhole ships, plus following the system.
/// </summary>
public static class AppLanguage
{
    /// <summary>The neutral resources are English, so this needs no satellite assembly.</summary>
    public const string English = "en";

    public const string Hungarian = "hu";

    /// <summary>Follow whatever Windows is set to.</summary>
    public const string Automatic = "auto";

    public static readonly string[] All = [Automatic, English, Hungarian];

    /// <summary>
    /// Turns a setting into a culture.
    ///
    /// "auto" resolves to Hungarian only when Windows is actually set to Hungarian;
    /// anything else falls back to English rather than to the system culture verbatim,
    /// because a German system has no German resources and would otherwise get keys.
    /// </summary>
    public static CultureInfo Resolve(string? setting)
    {
        var chosen = setting switch
        {
            Hungarian => Hungarian,
            English => English,
            _ => CultureInfo.CurrentUICulture.TwoLetterISOLanguageName == Hungarian
                ? Hungarian
                : English,
        };

        return CultureInfo.GetCultureInfo(chosen);
    }

    /// <summary>The label shown on the settings control for a stored value.</summary>
    public static string Label(string? setting) => setting switch
    {
        Hungarian => "Magyar",
        English => "English",
        _ => Loc.Current["SettingsLanguageAuto"],
    };
}
