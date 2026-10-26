using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;

namespace Keyhole.App.Controls;

/// <summary>One sample in the chart.</summary>
public readonly record struct ChartPoint(DateTimeOffset TimestampUtc, double Sent, double Received);

/// <summary>
/// Throughput over time: two filled series, upload and download, on one shared axis.
///
/// Deliberately a single y-scale. Up and down are the same measure in the same unit, so
/// one axis is what makes them comparable; a second scale would make a trickle look like
/// a flood.
///
/// Colours are categorical slots 1 and 2 of the reference palette, validated for
/// colour-vision deficiency against both surfaces. Identity is never carried by colour
/// alone: the legend names both series.
/// </summary>
public sealed class ThroughputChart : Control
{
    public static readonly StyledProperty<IReadOnlyList<ChartPoint>?> PointsProperty =
        AvaloniaProperty.Register<ThroughputChart, IReadOnlyList<ChartPoint>?>(nameof(Points));

    public static readonly StyledProperty<IBrush> SentBrushProperty =
        AvaloniaProperty.Register<ThroughputChart, IBrush>(
            nameof(SentBrush), new SolidColorBrush(Color.Parse("#3987e5")));

    public static readonly StyledProperty<IBrush> ReceivedBrushProperty =
        AvaloniaProperty.Register<ThroughputChart, IBrush>(
            nameof(ReceivedBrush), new SolidColorBrush(Color.Parse("#d95926")));

    public static readonly StyledProperty<IBrush> GridBrushProperty =
        AvaloniaProperty.Register<ThroughputChart, IBrush>(
            nameof(GridBrush), new SolidColorBrush(Color.Parse("#242935")));

    public static readonly StyledProperty<IBrush> TextBrushProperty =
        AvaloniaProperty.Register<ThroughputChart, IBrush>(
            nameof(TextBrush), new SolidColorBrush(Color.Parse("#7D8694")));

    static ThroughputChart()
    {
        AffectsRender<ThroughputChart>(
            PointsProperty, SentBrushProperty, ReceivedBrushProperty, GridBrushProperty, TextBrushProperty);
    }

    public IReadOnlyList<ChartPoint>? Points
    {
        get => GetValue(PointsProperty);
        set => SetValue(PointsProperty, value);
    }

    public IBrush SentBrush
    {
        get => GetValue(SentBrushProperty);
        set => SetValue(SentBrushProperty, value);
    }

    public IBrush ReceivedBrush
    {
        get => GetValue(ReceivedBrushProperty);
        set => SetValue(ReceivedBrushProperty, value);
    }

    public IBrush GridBrush
    {
        get => GetValue(GridBrushProperty);
        set => SetValue(GridBrushProperty, value);
    }

    public IBrush TextBrush
    {
        get => GetValue(TextBrushProperty);
        set => SetValue(TextBrushProperty, value);
    }

    private const double AxisWidth = 62;
    private const double TopPadding = 10;
    private const double BottomPadding = 20;

    public override void Render(DrawingContext context)
    {
        var points = Points;
        var width = Bounds.Width;
        var height = Bounds.Height;

        if (width <= AxisWidth + 10 || height <= TopPadding + BottomPadding + 10)
        {
            return;
        }

        var plot = new Rect(
            AxisWidth, TopPadding,
            width - AxisWidth - 8, height - TopPadding - BottomPadding);

        if (points is null || points.Count < 2)
        {
            DrawGrid(context, plot, 0);
            DrawPlaceholder(context, plot);
            return;
        }

        // Round the scale up to a readable unit so the axis reads 0 / 500 KB/s / 1 MB/s
        // rather than an arbitrary peak value.
        var peak = points.Max(p => Math.Max(p.Sent, p.Received));
        var scaleMax = NiceCeiling(peak);

        DrawGrid(context, plot, scaleMax);

        // Download underneath: it is usually the larger of the two, so drawing it first
        // keeps the smaller upload series visible on top rather than hidden behind it.
        DrawSeries(context, plot, points, scaleMax, p => p.Received, ReceivedBrush);
        DrawSeries(context, plot, points, scaleMax, p => p.Sent, SentBrush);
    }

    private void DrawGrid(DrawingContext context, Rect plot, double scaleMax)
    {
        var pen = new Pen(GridBrush, 1);
        const int lines = 4;

        for (var i = 0; i <= lines; i++)
        {
            var y = plot.Bottom - (plot.Height * i / lines);
            context.DrawLine(pen, new Point(plot.Left, y), new Point(plot.Right, y));

            var label = scaleMax > 0
                ? FormatRate(scaleMax * i / lines)
                : i == 0 ? "0" : "";

            if (label.Length == 0)
            {
                continue;
            }

            var text = new FormattedText(
                label,
                CultureInfo.InvariantCulture,
                FlowDirection.LeftToRight,
                Typeface.Default,
                10,
                TextBrush);

            context.DrawText(text, new Point(plot.Left - text.Width - 6, y - (text.Height / 2)));
        }
    }

    private void DrawPlaceholder(DrawingContext context, Rect plot)
    {
        var text = new FormattedText(
            "Collecting data…",
            CultureInfo.InvariantCulture,
            FlowDirection.LeftToRight,
            Typeface.Default,
            11,
            TextBrush);

        context.DrawText(text, new Point(
            plot.Center.X - (text.Width / 2),
            plot.Center.Y - (text.Height / 2)));
    }

    private static void DrawSeries(
        DrawingContext context,
        Rect plot,
        IReadOnlyList<ChartPoint> points,
        double scaleMax,
        Func<ChartPoint, double> select,
        IBrush brush)
    {
        var start = points[0].TimestampUtc;
        var span = (points[^1].TimestampUtc - start).TotalSeconds;
        if (span <= 0)
        {
            return;
        }

        var geometry = new StreamGeometry();

        using (var ctx = geometry.Open())
        {
            var first = ToPoint(points[0]);

            // Anchor the fill to the baseline so the area reads as volume above zero.
            ctx.BeginFigure(new Point(first.X, plot.Bottom), isFilled: true);
            ctx.LineTo(first);

            for (var i = 1; i < points.Count; i++)
            {
                ctx.LineTo(ToPoint(points[i]));
            }

            ctx.LineTo(new Point(ToPoint(points[^1]).X, plot.Bottom));
            ctx.EndFigure(true);
        }

        var colour = (brush as SolidColorBrush)?.Color ?? Colors.Gray;

        // Translucent fill under a solid 2px line: the line keeps the series readable
        // where the two areas overlap, which a flat fill alone would not.
        var fill = new SolidColorBrush(Color.FromArgb(70, colour.R, colour.G, colour.B));
        context.DrawGeometry(fill, null, geometry);

        var line = new StreamGeometry();
        using (var ctx = line.Open())
        {
            ctx.BeginFigure(ToPoint(points[0]), isFilled: false);
            for (var i = 1; i < points.Count; i++)
            {
                ctx.LineTo(ToPoint(points[i]));
            }

            ctx.EndFigure(false);
        }

        context.DrawGeometry(null, new Pen(brush, 2), line);

        Point ToPoint(ChartPoint point)
        {
            var x = plot.Left + (plot.Width * (point.TimestampUtc - start).TotalSeconds / span);
            var value = scaleMax > 0 ? Math.Min(select(point) / scaleMax, 1) : 0;
            return new Point(x, plot.Bottom - (plot.Height * value));
        }
    }

    /// <summary>
    /// Rounds a peak up to 1, 2 or 5 times a power of 1024 so gridline labels land on
    /// values a person reads without decoding.
    /// </summary>
    internal static double NiceCeiling(double peak)
    {
        if (peak <= 0)
        {
            // An idle machine still needs a scale, otherwise the axis reads 0/0/0/0.
            return 1024;
        }

        var magnitude = Math.Pow(1024, Math.Floor(Math.Log(peak, 1024)));
        var normalised = peak / magnitude;

        var step = normalised switch
        {
            <= 1 => 1,
            <= 2 => 2,
            <= 5 => 5,
            _ => 10,
        };

        return step * magnitude;
    }

    internal static string FormatRate(double bytesPerSecond) => bytesPerSecond switch
    {
        < 1 => "0",
        < 1024 => $"{bytesPerSecond:F0} B/s",
        < 1024 * 1024 => $"{bytesPerSecond / 1024:F0} KB/s",
        < 1024d * 1024 * 1024 => $"{bytesPerSecond / (1024 * 1024):F1} MB/s",
        _ => $"{bytesPerSecond / (1024d * 1024 * 1024):F2} GB/s",
    };
}
