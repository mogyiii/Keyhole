using Avalonia.Data;
using Avalonia.Markup.Xaml;

namespace Keyhole.App.Localization;

/// <summary>
/// Looks up a string by key: <c>Text="{l:Translate HostsTabHeader}"</c>.
///
/// The markup name drops the "Extension" suffix, which XAML strips by convention.
///
/// Returns a binding rather than the string itself, which is what makes switching
/// language refresh the window instead of needing a restart. The binding's source is the
/// <see cref="Loc"/> singleton rather than the data context, so the same syntax works on a
/// DataGrid column header — those are outside the visual tree and have no data context to
/// resolve against, which is the thing that rules out a plain binding here.
/// </summary>
public sealed class TranslateExtension(string key) : MarkupExtension
{
    /// <summary>The resource key. Positional, so the markup stays short.</summary>
    public string Key { get; set; } = key;

    public override object ProvideValue(IServiceProvider serviceProvider) =>
        new Binding
        {
            Source = Loc.Current,
            Path = $"[{Key}]",
            Mode = BindingMode.OneWay,
        };
}
