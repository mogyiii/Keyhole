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

    /// <summary>
    /// Why the source is not running, in English, for the log. Null when running.
    /// </summary>
    string? UnavailableReason { get; }

    /// <summary>
    /// The same answer as a code the UI can translate, from
    /// <see cref="Ipc.ReasonCodes"/>. Null when running.
    ///
    /// Two fields rather than one because they serve different readers: the sentence goes
    /// in the service log, where English is easier to search and to paste into an issue,
    /// and the code goes to the interface, which has to say it in the user's language.
    /// </summary>
    string? UnavailableCode { get; }

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
public sealed class NullByteCounterSource(string reason, string? code = null) : IByteCounterSource
{
    public bool IsRunning => false;

    public string? UnavailableReason { get; } = reason;

    public string? UnavailableCode { get; } = code ?? Ipc.ReasonCodes.EtwUnavailable;

    public ByteCounts GetCounts(ConnectionKey key) => ByteCounts.Zero;

    public IReadOnlyList<UdpPeer> GetUdpPeers(int processId, int localPort) => [];
}
