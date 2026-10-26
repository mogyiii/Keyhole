using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Keyhole.Core.Monitoring;

/// <summary>
/// Turns a series of socket snapshots into connection lifetimes.
///
/// Each sample is diffed against the previous one: keys that appeared are new flows, keys
/// that vanished have ended. Sampling can miss a connection that opens and closes inside
/// one interval — ETW covers that gap for byte counts, but for "which apps are talking",
/// a short interval is accurate enough and costs a fraction as much.
/// </summary>
public sealed class FlowTracker(
    ISocketTableReader sockets,
    IProcessResolver processes,
    IHostnameResolver hostnames,
    IByteCounterSource? bytes = null,
    ILogger<FlowTracker>? logger = null)
{
    private readonly IByteCounterSource _bytes =
        bytes ?? new NullByteCounterSource("No byte counter configured.");

    private readonly ILogger _logger = logger ?? NullLogger<FlowTracker>.Instance;
    private readonly Dictionary<ConnectionKey, TrackedFlow> _active = [];
    private readonly Lock _gate = new();

    /// <summary>
    /// Flows that ended recently, kept so the UI can still show what just happened.
    /// Without this, a connection would vanish from the list the instant it closed.
    /// </summary>
    private readonly List<TrackedFlow> _recentlyClosed = [];

    private static readonly TimeSpan ClosedRetention = TimeSpan.FromMinutes(5);
    private const int MaxRecentlyClosed = 2000;

    /// <summary>How much of the throughput graph is kept.</summary>
    public static TimeSpan GraphWindow => TimeSpan.FromMinutes(5);

    /// <summary>Machine-wide throughput, for the dashboard graph.</summary>
    public ThroughputHistory TotalThroughput { get; } = new(GraphWindow);

    /// <summary>
    /// Per-application rates, keyed the same way <see cref="GetAppActivity"/> groups.
    /// Entries are dropped when an app stops appearing, so a long session does not
    /// accumulate history for every program that ever opened a socket.
    /// </summary>
    private readonly Dictionary<string, ThroughputHistory> _appThroughput =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Flows observed since the tracker started, active and recently closed.</summary>
    public IReadOnlyList<TrackedFlow> Snapshot()
    {
        lock (_gate)
        {
            return [.. _active.Values, .. _recentlyClosed];
        }
    }

    /// <summary>
    /// Reads the socket table once and folds it into tracked state.
    /// Returns what changed, so callers can persist only the deltas.
    /// </summary>
    public SampleResult Sample()
    {
        var now = DateTimeOffset.UtcNow;

        IReadOnlyList<NetworkConnection> current;
        try
        {
            current = sockets.ReadAll();
        }
        catch (Exception ex)
        {
            // A failed read must not kill the monitoring loop; the next sample may succeed.
            _logger.LogError(ex, "Socket table read failed; skipping this sample.");
            return new SampleResult([], [], 0);
        }

        var opened = new List<TrackedFlow>();
        var closed = new List<TrackedFlow>();

        lock (_gate)
        {
            var seen = new HashSet<ConnectionKey>(current.Count);

            foreach (var connection in current)
            {
                // Listeners are not traffic. Including them would fill the app list with
                // every server socket on the machine, pointing at 0.0.0.0.
                if (connection.IsListener)
                {
                    continue;
                }

                var key = connection.Key;
                seen.Add(key);

                if (_active.TryGetValue(key, out var existing))
                {
                    var counts = _bytes.GetCounts(key);

                    _active[key] = existing with
                    {
                        Connection = connection,
                        LastSeenUtc = now,
                        // Retry the name each sample: the first lookup returns null while
                        // the background query is still in flight.
                        RemoteHostname = existing.RemoteHostname ?? hostnames.TryGet(connection.RemoteAddress),

                        // ETW totals are cumulative, so assign rather than accumulate.
                        // Keep the previous figures if counting is unavailable, otherwise
                        // every sample would reset a flow's totals to zero.
                        BytesSent = counts.IsEmpty ? existing.BytesSent : counts.Sent,
                        BytesReceived = counts.IsEmpty ? existing.BytesReceived : counts.Received,
                    };

                    continue;
                }

                // Only reached for connections not already tracked. A socket first seen
                // with no owning process — a TIME_WAIT left over from before monitoring
                // started — belongs to no application and would otherwise pile up under
                // "System Idle Process", dominating the list with finished activity.
                if (connection.IsUnattributable)
                {
                    continue;
                }

                var flow = new TrackedFlow
                {
                    Key = key,
                    Connection = connection,
                    Process = processes.Resolve(connection.ProcessId),
                    StartedUtc = now,
                    LastSeenUtc = now,
                    RemoteHostname = hostnames.TryGet(connection.RemoteAddress),
                };

                _active[key] = flow;
                opened.Add(flow);
            }

            foreach (var key in _active.Keys.Where(k => !seen.Contains(k)).ToList())
            {
                var ended = _active[key] with { EndedUtc = now };
                _active.Remove(key);
                _recentlyClosed.Add(ended);
                closed.Add(ended);
            }

            PruneClosed(now);

            return new SampleResult(opened, closed, _active.Count);
        }
    }

    private void PruneClosed(DateTimeOffset now)
    {
        _recentlyClosed.RemoveAll(f => f.EndedUtc is { } ended && now - ended > ClosedRetention);

        if (_recentlyClosed.Count > MaxRecentlyClosed)
        {
            // A burst of short-lived connections could outrun the time-based prune,
            // so cap the list as well and drop the oldest.
            _recentlyClosed.RemoveRange(0, _recentlyClosed.Count - MaxRecentlyClosed);
        }
    }

    /// <summary>
    /// Collapses flows into one row per program. Grouping is by executable path, so the
    /// same program running as several processes reads as one entry — which is what a
    /// user means by "what is Chrome doing".
    /// </summary>
    public IReadOnlyList<AppActivity> GetAppActivity()
    {
        var flows = Snapshot();
        var now = DateTimeOffset.UtcNow;

        var activity = flows
            .GroupBy(f => f.Process.ExecutablePath ?? f.Process.DisplayName, StringComparer.OrdinalIgnoreCase)
            .Select(group =>
            {
                var identity = group.First().Process;
                var sent = group.Sum(f => f.BytesSent);
                var received = group.Sum(f => f.BytesReceived);
                var rate = RecordAppThroughput(group.Key, sent, received, now);

                return new AppActivity
                {
                    SentRate = rate.BytesSentPerSecond,
                    ReceivedRate = rate.BytesReceivedPerSecond,
                    DisplayName = identity.DisplayName,
                    ExecutablePath = identity.ExecutablePath,
                    Publisher = identity.Publisher,
                    Signature = identity.Signature,
                    ActiveConnections = group.Count(f => f.IsActive),
                    TotalConnections = group.Count(),
                    BytesSent = sent,
                    BytesReceived = received,
                    FirstSeenUtc = group.Min(f => f.StartedUtc),
                    LastActiveUtc = group.Max(f => f.LastSeenUtc),
                    RecentRemoteHosts = group
                        .OrderByDescending(f => f.LastSeenUtc)
                        .Select(f => f.RemoteHostname ?? f.Connection.RemoteAddress.ToString())
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .Take(10)
                        .ToList(),
                    ProcessIds = group
                        .Where(f => f.IsActive)
                        .Select(f => f.Connection.ProcessId)
                        .Distinct()
                        .OrderBy(pid => pid)
                        .ToList(),
                };
            })
            .OrderByDescending(a => a.LastActiveUtc)
            .ToList();

        TotalThroughput.Record(
            activity.Sum(a => a.BytesSent),
            activity.Sum(a => a.BytesReceived),
            now);

        PruneAppThroughput(activity.Select(a => a.ExecutablePath ?? a.DisplayName));

        return activity;
    }

    private ThroughputPoint RecordAppThroughput(string key, long sent, long received, DateTimeOffset now)
    {
        lock (_gate)
        {
            if (!_appThroughput.TryGetValue(key, out var history))
            {
                history = new ThroughputHistory(GraphWindow);
                _appThroughput[key] = history;
            }

            return history.Record(sent, received, now);
        }
    }

    private void PruneAppThroughput(IEnumerable<string> liveKeys)
    {
        var live = liveKeys.ToHashSet(StringComparer.OrdinalIgnoreCase);

        lock (_gate)
        {
            foreach (var key in _appThroughput.Keys.Where(k => !live.Contains(k)).ToList())
            {
                _appThroughput.Remove(key);
            }
        }
    }

    /// <summary>Throughput history for one application, for its detail graph.</summary>
    public IReadOnlyList<ThroughputPoint> GetAppThroughput(string key)
    {
        lock (_gate)
        {
            return _appThroughput.TryGetValue(key, out var history) ? history.Snapshot() : [];
        }
    }
}

/// <summary>What one sampling pass changed.</summary>
public sealed record SampleResult(
    IReadOnlyList<TrackedFlow> Opened,
    IReadOnlyList<TrackedFlow> Closed,
    int ActiveCount);
