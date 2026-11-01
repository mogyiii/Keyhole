using Keyhole.Core.Monitoring;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Keyhole.Core.Capture.Recording;

/// <summary>
/// Keeps track of which local ports belong to the application being captured.
///
/// This is what keeps a capture session from becoming a recording of everything the
/// machine does. An adapter hands over every packet it sees, so without a scope the pcap
/// would hold every other application's traffic too — a privacy problem, not just a disk
/// one.
///
/// The scope cannot be fixed at the start, for two reasons. A browser opens and closes
/// connections throughout a session, so its port set changes constantly; and the real work
/// happens in child processes, which do not exist yet when the capture begins. A capture
/// filter compiled into the driver cannot be rewritten while running, so the decision is
/// made per packet in managed code against a set refreshed from the socket table.
/// </summary>
public sealed class TargetPortTracker(
    ISocketTableReader sockets,
    IProcessTreeReader processTree,
    ILogger<TargetPortTracker>? logger = null)
{
    private readonly ILogger _logger = logger ?? NullLogger<TargetPortTracker>.Instance;

    /// <summary>
    /// How often the port set is rebuilt while nothing demands it sooner.
    ///
    /// A second is cheap and catches connections that live long enough to matter. It is
    /// not enough on its own: see <see cref="RefreshForNewConnection"/>.
    /// </summary>
    public static TimeSpan RefreshInterval => TimeSpan.FromSeconds(1);

    /// <summary>
    /// The shortest gap between refreshes forced by a new connection.
    ///
    /// A refresh enumerates every socket on the machine and walks the process list, so it
    /// cannot run per packet. Twenty times a second is affordable, and a connection's SYN
    /// and its ClientHello are never that far apart.
    /// </summary>
    private static readonly TimeSpan MinimumForcedGap = TimeSpan.FromMilliseconds(50);

    private DateTimeOffset _lastForcedRefresh = DateTimeOffset.MinValue;

    private readonly Lock _gate = new();

    /// <summary>
    /// Ports currently owned by the target. Swapped wholesale on refresh rather than
    /// mutated, so the capture thread never sees a half-built set.
    /// </summary>
    private HashSet<int> _ports = [];

    /// <summary>
    /// Ports seen at any point during the session.
    ///
    /// Kept separately because a connection's last packets arrive after the socket is
    /// gone: a FIN or RST for a port that closed a moment ago still belongs to this
    /// session, and dropping it would truncate the very end of every conversation —
    /// which is where a TLS session's closure and a response's last bytes live.
    /// </summary>
    private readonly HashSet<int> _historicPorts = [];

    private DateTimeOffset _lastRefresh = DateTimeOffset.MinValue;

    /// <summary>PIDs the target owns, for diagnostics and for the UI to report.</summary>
    public int ProcessCount { get; private set; }

    /// <summary>
    /// Rebuilds the port set if it is stale. Cheap to call per packet: it returns
    /// immediately unless the interval has elapsed.
    /// </summary>
    /// <returns>True when a refresh actually ran, so the caller can act on a wider scope.</returns>
    public bool RefreshIfStale(int rootProcessId, string? executablePath, DateTimeOffset now)
    {
        lock (_gate)
        {
            if (now - _lastRefresh < RefreshInterval)
            {
                return false;
            }

            _lastRefresh = now;
        }

        Refresh(rootProcessId, executablePath);
        return true;
    }

    /// <summary>
    /// Rebuilds the port set because a connection is being opened right now.
    ///
    /// This exists because the periodic refresh is not enough, and the live run that
    /// proved it is worth recording: a browser session recorded 40 MB of packets and
    /// yielded one decodable request out of five TLS connections. The missing piece was
    /// always the same — the ClientHello.
    ///
    /// A connection opened between two refreshes has no owned port yet, so its first
    /// packets are dropped. For most traffic that would cost a little data; for TLS it
    /// costs everything, because the ClientHello carries the client random that joins the
    /// connection to its key. Without it the capture holds a perfectly recorded
    /// conversation that nothing can ever read.
    ///
    /// A SYN is the signal: the socket exists in the OS table by the time its SYN goes
    /// out, so refreshing on one finds the port immediately — before the handshake it
    /// belongs to.
    /// </summary>
    /// <returns>True when a refresh actually ran, so the caller can re-test the packet.</returns>
    public bool RefreshForNewConnection(
        int rootProcessId, string? executablePath, DateTimeOffset now)
    {
        lock (_gate)
        {
            if (now - _lastForcedRefresh < MinimumForcedGap)
            {
                return false;
            }

            _lastForcedRefresh = now;
            _lastRefresh = now;
        }

        Refresh(rootProcessId, executablePath);
        return true;
    }

    /// <summary>Rebuilds the port set now.</summary>
    public void Refresh(int rootProcessId, string? executablePath)
    {
        HashSet<int> owners;
        try
        {
            owners = processTree.DescendantsOf(rootProcessId, executablePath);
        }
        catch (Exception ex)
        {
            // Losing the tree would silently narrow the capture to the launcher process.
            // Keep the previous set rather than quietly recording less than asked.
            _logger.LogWarning(ex, "Could not enumerate the capture target's processes.");
            return;
        }

        HashSet<int> ports = [];

        try
        {
            foreach (var connection in sockets.ReadAll())
            {
                if (owners.Contains(connection.ProcessId))
                {
                    ports.Add(connection.LocalPort);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not read the socket table while scoping a capture.");
            return;
        }

        lock (_gate)
        {
            _ports = ports;
            _historicPorts.UnionWith(ports);
            ProcessCount = owners.Count;
        }
    }

    /// <summary>
    /// Whether a packet with these local-side candidates belongs to the target.
    ///
    /// Both ports are offered because a captured packet gives no direction: an inbound
    /// packet's destination port is the local one, an outbound packet's source port is.
    /// Checking both is what makes a single test work for each direction.
    /// </summary>
    public bool Owns(int sourcePort, int destinationPort)
    {
        lock (_gate)
        {
            return _historicPorts.Contains(sourcePort) || _historicPorts.Contains(destinationPort);
        }
    }

    /// <summary>Ports the target holds right now, for reporting.</summary>
    public int ActivePortCount
    {
        get
        {
            lock (_gate)
            {
                return _ports.Count;
            }
        }
    }
}

/// <summary>
/// Resolves which processes make up the application being captured.
/// </summary>
public interface IProcessTreeReader
{
    /// <summary>
    /// The process ids belonging to one launched application, including
    /// <paramref name="rootProcessId"/> itself.
    /// </summary>
    /// <param name="executablePath">
    /// The launched binary. Included because matching the tree alone is not enough: a
    /// browser re-parents its helpers, so a child whose parent has exited would drop out
    /// of the tree while still doing the application's network work.
    /// </param>
    HashSet<int> DescendantsOf(int rootProcessId, string? executablePath);
}
