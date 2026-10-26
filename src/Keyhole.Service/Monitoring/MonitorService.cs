using Keyhole.Core;
using Keyhole.Core.Monitoring;
using Keyhole.Core.Storage;
using Keyhole.Native;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Keyhole.Service.Monitoring;

/// <summary>
/// Samples the socket table on a fixed interval and persists what changed.
/// </summary>
public sealed class MonitorService(
    FlowTracker tracker,
    FlowRepository repository,
    EtwByteCounter byteCounter,
    ILogger<MonitorService> logger) : BackgroundService
{
    /// <summary>
    /// Short enough to catch most connections, long enough to stay cheap. A full sample
    /// is a couple of milliseconds, so this is well under 1% of a core.
    /// </summary>
    public static TimeSpan SampleInterval => TimeSpan.FromSeconds(2);

    private static readonly TimeSpan PruneInterval = TimeSpan.FromHours(6);

    private DateTimeOffset _lastPruneUtc = DateTimeOffset.UtcNow;

    /// <summary>Set once the first sample lands, so status can report real state.</summary>
    public bool HasSampled { get; private set; }

    public int ActiveConnections { get; private set; }

    /// <summary>Why byte counting is unavailable, or null when it is running.</summary>
    public string? ByteCountingUnavailableReason =>
        byteCounter.IsRunning ? null : byteCounter.UnavailableReason;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Flows live at the time this process starts were never seen to close by the
        // previous run, so they would stay "active" in history indefinitely.
        var orphaned = repository.CloseOrphanedFlows();
        if (orphaned > 0)
        {
            logger.LogInformation(
                "Closed {Count} flows left open by a previous run, dated to when they were last seen.",
                orphaned);
        }

        // Connection tracking works unelevated; only byte counting needs the ETW session.
        // A failure here must not stop monitoring, so the result is reported, not thrown.
        if (!byteCounter.TryStart())
        {
            logger.LogWarning(
                "Byte counting unavailable: {Reason} Connection tracking continues without volume figures.",
                byteCounter.UnavailableReason);
        }

        logger.LogInformation("Flow monitoring started, sampling every {Interval}.", SampleInterval);

        using var timer = new PeriodicTimer(SampleInterval);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var sample = tracker.Sample();
                repository.RecordSample(sample);

                HasSampled = true;
                ActiveConnections = sample.ActiveCount;

                if (sample.Opened.Count > 0 || sample.Closed.Count > 0)
                {
                    logger.LogDebug(
                        "Sample: +{Opened} -{Closed}, {Active} active.",
                        sample.Opened.Count, sample.Closed.Count, sample.ActiveCount);
                }

                MaybePrune();
            }
            catch (Exception ex)
            {
                // Monitoring must survive a bad sample; the next tick may work.
                logger.LogError(ex, "Sampling pass failed.");
            }

            try
            {
                await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }

        logger.LogInformation("Flow monitoring stopped.");
    }

    private void MaybePrune()
    {
        if (DateTimeOffset.UtcNow - _lastPruneUtc < PruneInterval)
        {
            return;
        }

        _lastPruneUtc = DateTimeOffset.UtcNow;

        // Re-read each time: the user can change retention in the UI while the service
        // runs, and re-reading a small JSON file every six hours costs nothing.
        var retention = SettingsStore.Load().Retention;

        var removed = repository.PruneOlderThan(retention);
        if (removed > 0)
        {
            logger.LogInformation("Pruned {Count} flows older than {Retention}.", removed, retention);
        }
    }
}
