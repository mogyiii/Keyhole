namespace Keyhole.Core.Monitoring;

/// <summary>
/// Supplies per-connection byte totals. The socket table reports who is connected but
/// never how much has moved, so this is the only route to volume figures.
/// </summary>
public interface IByteCounterSource
{
    /// <summary>
    /// True once counting is actually running. False means the source could not start —
    /// almost always missing elevation — and every total will read zero.
    /// </summary>
    bool IsRunning { get; }

    /// <summary>Why the source is not running, for the UI to explain. Null when running.</summary>
    string? UnavailableReason { get; }

    /// <summary>Bytes seen for a connection since monitoring started.</summary>
    ByteCounts GetCounts(ConnectionKey key);

    /// <summary>
    /// Peers observed for one process's UDP socket. The UDP socket table carries no remote
    /// endpoint at all, so without this UDP traffic — including QUIC, which is how a modern
    /// browser moves most of its data — has no visible destination.
    ///
    /// Keyed by process as well as port: two applications can hold the same local port
    /// number on different sockets, and merging them would attribute one app's peers to
    /// the other.
    /// </summary>
    IReadOnlyList<UdpPeer> GetUdpPeers(int processId, int localPort);
}

public readonly record struct ByteCounts(long Sent, long Received)
{
    public static ByteCounts Zero => new(0, 0);

    public bool IsEmpty => Sent == 0 && Received == 0;
}

public readonly record struct UdpPeer(string RemoteAddress, int RemotePort, long Sent, long Received);

/// <summary>A source that reports nothing, used when byte counting is unavailable.</summary>
public sealed class NullByteCounterSource(string reason) : IByteCounterSource
{
    public bool IsRunning => false;

    public string? UnavailableReason { get; } = reason;

    public ByteCounts GetCounts(ConnectionKey key) => ByteCounts.Zero;

    public IReadOnlyList<UdpPeer> GetUdpPeers(int processId, int localPort) => [];
}
