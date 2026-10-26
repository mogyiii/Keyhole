namespace Keyhole.Core.Monitoring;

/// <summary>
/// One moment in the throughput graph.
/// </summary>
public readonly record struct ThroughputPoint(
    DateTimeOffset TimestampUtc,
    double BytesSentPerSecond,
    double BytesReceivedPerSecond);

/// <summary>
/// Turns cumulative byte totals into rates, and keeps a short rolling history for the
/// dashboard graph.
///
/// Rates are derived from the difference between consecutive samples rather than stored
/// directly: ETW reports lifetime totals per connection, and a rate is what a person
/// actually reads off a graph.
/// </summary>
public sealed class ThroughputHistory(TimeSpan window, int maxPoints = 300)
{
    private readonly Queue<ThroughputPoint> _points = new();
    private readonly Lock _gate = new();

    private long _lastSent;
    private long _lastReceived;
    private DateTimeOffset _lastSampleUtc;
    private bool _hasBaseline;

    /// <summary>Most recent sent rate, in bytes per second.</summary>
    public double CurrentSentRate { get; private set; }

    /// <summary>Most recent received rate, in bytes per second.</summary>
    public double CurrentReceivedRate { get; private set; }

    /// <summary>
    /// Records a cumulative total and returns the rate since the previous record.
    /// The first call establishes a baseline and reports zero: there is no earlier
    /// sample to measure against, and assuming one would invent a huge initial spike.
    /// </summary>
    public ThroughputPoint Record(long totalSent, long totalReceived, DateTimeOffset nowUtc)
    {
        lock (_gate)
        {
            if (!_hasBaseline)
            {
                _lastSent = totalSent;
                _lastReceived = totalReceived;
                _lastSampleUtc = nowUtc;
                _hasBaseline = true;

                return Append(new ThroughputPoint(nowUtc, 0, 0));
            }

            var elapsed = (nowUtc - _lastSampleUtc).TotalSeconds;
            if (elapsed <= 0)
            {
                // Two samples in the same instant, or a clock that went backwards.
                // Dividing by this would produce infinity.
                return new ThroughputPoint(nowUtc, CurrentSentRate, CurrentReceivedRate);
            }

            // Totals can drop: a connection closing removes its contribution, and an ETW
            // session restart resets counters. A negative delta is not negative traffic,
            // so treat it as a fresh baseline rather than reporting a negative rate.
            var sentDelta = Math.Max(0, totalSent - _lastSent);
            var receivedDelta = Math.Max(0, totalReceived - _lastReceived);

            CurrentSentRate = sentDelta / elapsed;
            CurrentReceivedRate = receivedDelta / elapsed;

            _lastSent = totalSent;
            _lastReceived = totalReceived;
            _lastSampleUtc = nowUtc;

            return Append(new ThroughputPoint(nowUtc, CurrentSentRate, CurrentReceivedRate));
        }
    }

    /// <summary>History oldest-first, suitable for plotting left to right.</summary>
    public IReadOnlyList<ThroughputPoint> Snapshot()
    {
        lock (_gate)
        {
            return [.. _points];
        }
    }

    private ThroughputPoint Append(ThroughputPoint point)
    {
        _points.Enqueue(point);

        var cutoff = point.TimestampUtc - window;
        while (_points.Count > 0 && _points.Peek().TimestampUtc < cutoff)
        {
            _points.Dequeue();
        }

        // Also cap by count: a very short sampling interval could otherwise fill the
        // window with more points than any graph can show.
        while (_points.Count > maxPoints)
        {
            _points.Dequeue();
        }

        return point;
    }
}
