using System;
using System.Globalization;
using Avalonia.Data.Converters;
using Avalonia.Media;
using Keyhole.App.ViewModels;

namespace Keyhole.App.Converters;

/// <summary>
/// Maps a <see cref="ConnectionState"/> to its indicator colour. Colour is redundant with the
/// adjacent text label, never the only signal.
/// </summary>
public sealed class ConnectionStateToBrushConverter : IValueConverter
{
    private static readonly SolidColorBrush Connected = new(Color.Parse("#3FB950"));
    private static readonly SolidColorBrush Pending = new(Color.Parse("#D29922"));
    private static readonly SolidColorBrush Failed = new(Color.Parse("#F85149"));
    private static readonly SolidColorBrush Idle = new(Color.Parse("#6E7681"));

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        (value as ConnectionState?) switch
        {
            ConnectionState.Connected => Connected,
            ConnectionState.Connecting => Pending,
            ConnectionState.Unavailable or ConnectionState.Error => Failed,
            _ => Idle,
        };

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException("ConnectionStateToBrushConverter is one-way.");
}
