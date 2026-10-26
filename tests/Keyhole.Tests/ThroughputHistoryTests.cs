using Keyhole.Core.Monitoring;

namespace Keyhole.Tests;

public class ThroughputHistoryTests
{
    private static readonly DateTimeOffset T0 = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);

    private static ThroughputHistory NewHistory(int windowMinutes = 5) =>
        new(TimeSpan.FromMinutes(windowMinutes));

    [Fact]
    public void First_sample_reports_zero()
    {
        var history = NewHistory();

        var point = history.Record(1_000_000, 2_000_000, T0);

        // There is no earlier sample to measure against. Treating the running total as
        // the first second's traffic would show a huge spike the moment Keyhole starts.
        Assert.Equal(0, point.BytesSentPerSecond);
        Assert.Equal(0, point.BytesReceivedPerSecond);
    }

    [Fact]
    public void Rate_is_the_delta_over_elapsed_time()
    {
        var history = NewHistory();

        history.Record(1000, 2000, T0);
        var point = history.Record(3000, 6000, T0.AddSeconds(2));

        // 2000 bytes over 2 seconds.
        Assert.Equal(1000, point.BytesSentPerSecond);
        Assert.Equal(2000, point.BytesReceivedPerSecond);
    }

    [Fact]
    public void Rate_accounts_for_a_non_standard_interval()
    {
        var history = NewHistory();

        history.Record(0, 0, T0);
        var point = history.Record(500, 0, T0.AddMilliseconds(500));

        // Assuming a fixed interval would report 500 B/s instead of 1000.
        Assert.Equal(1000, point.BytesSentPerSecond);
    }

    [Fact]
    public void Totals_going_backwards_do_not_produce_a_negative_rate()
    {
        var history = NewHistory();

        history.Record(10_000, 10_000, T0);

        // A closing connection removes its bytes from the total, and an ETW restart
        // resets counters. Neither is negative traffic.
        var point = history.Record(4_000, 4_000, T0.AddSeconds(2));

        Assert.Equal(0, point.BytesSentPerSecond);
        Assert.Equal(0, point.BytesReceivedPerSecond);
    }

    [Fact]
    public void Rate_recovers_after_a_counter_reset()
    {
        var history = NewHistory();

        history.Record(10_000, 0, T0);
        history.Record(0, 0, T0.AddSeconds(2));
        var point = history.Record(2_000, 0, T0.AddSeconds(4));

        // The reset re-baselines, so the next interval measures from the new total
        // rather than reporting nothing forever.
        Assert.Equal(1000, point.BytesSentPerSecond);
    }

    [Fact]
    public void Two_samples_at_the_same_instant_do_not_divide_by_zero()
    {
        var history = NewHistory();

        history.Record(0, 0, T0);
        history.Record(1000, 1000, T0.AddSeconds(1));
        var point = history.Record(5000, 5000, T0.AddSeconds(1));

        Assert.False(double.IsInfinity(point.BytesSentPerSecond));
        Assert.False(double.IsNaN(point.BytesSentPerSecond));
    }

    [Fact]
    public void A_clock_moving_backwards_does_not_produce_a_negative_rate()
    {
        var history = NewHistory();

        history.Record(0, 0, T0.AddSeconds(10));
        var point = history.Record(1000, 1000, T0);

        Assert.True(point.BytesSentPerSecond >= 0);
    }

    [Fact]
    public void History_keeps_points_in_order()
    {
        var history = NewHistory();

        for (var i = 0; i < 10; i++)
        {
            history.Record(i * 1000, 0, T0.AddSeconds(i));
        }

        var points = history.Snapshot();

        Assert.Equal(10, points.Count);
        Assert.Equal(
            points.OrderBy(p => p.TimestampUtc).Select(p => p.TimestampUtc),
            points.Select(p => p.TimestampUtc));
    }

    [Fact]
    public void Points_outside_the_window_are_dropped()
    {
        var history = new ThroughputHistory(TimeSpan.FromSeconds(10));

        for (var i = 0; i < 30; i++)
        {
            history.Record(i * 1000, 0, T0.AddSeconds(i));
        }

        var points = history.Snapshot();

        // A graph showing the last 10 seconds must not retain half an hour of samples.
        Assert.True(points.Count <= 11, $"Kept {points.Count} points for a 10s window.");
        Assert.All(points, p => Assert.True(p.TimestampUtc >= T0.AddSeconds(29 - 10)));
    }

    [Fact]
    public void History_is_capped_by_count_as_well_as_time()
    {
        var history = new ThroughputHistory(TimeSpan.FromDays(1), maxPoints: 50);

        for (var i = 0; i < 500; i++)
        {
            history.Record(i * 100, 0, T0.AddMilliseconds(i * 10));
        }

        // A short sampling interval inside a long window would otherwise accumulate
        // far more points than any graph can draw.
        Assert.Equal(50, history.Snapshot().Count);
    }

    [Fact]
    public void Current_rate_tracks_the_latest_sample()
    {
        var history = NewHistory();

        history.Record(0, 0, T0);
        history.Record(1000, 2000, T0.AddSeconds(1));

        Assert.Equal(1000, history.CurrentSentRate);
        Assert.Equal(2000, history.CurrentReceivedRate);
    }

    [Fact]
    public void Idle_period_reports_zero_rather_than_the_last_rate()
    {
        var history = NewHistory();

        history.Record(0, 0, T0);
        history.Record(10_000, 0, T0.AddSeconds(1));

        // Totals unchanged: the app stopped talking.
        var point = history.Record(10_000, 0, T0.AddSeconds(2));

        Assert.Equal(0, point.BytesSentPerSecond);
        Assert.Equal(0, history.CurrentSentRate);
    }
}
