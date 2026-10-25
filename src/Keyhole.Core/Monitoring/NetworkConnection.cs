using System.Net;

namespace Keyhole.Core.Monitoring;

public enum TransportProtocol
{
    Tcp,
    Udp,
}

/// <summary>
/// TCP states from the Windows MIB_TCP_STATE enum. UDP is connectionless and always
/// reports <see cref="None"/>.
/// </summary>
public enum TcpConnectionState
{
    None = 0,
    Closed = 1,
    Listen = 2,
    SynSent = 3,
    SynReceived = 4,
    Established = 5,
    FinWait1 = 6,
    FinWait2 = 7,
    CloseWait = 8,
    Closing = 9,
    LastAck = 10,
    TimeWait = 11,
    DeleteTcb = 12,
}

/// <summary>
/// One socket as the OS reports it, before any process or DNS enrichment.
/// </summary>
public sealed record NetworkConnection
{
    public required int ProcessId { get; init; }
    public required TransportProtocol Protocol { get; init; }
    public required IPAddress LocalAddress { get; init; }
    public required int LocalPort { get; init; }
    public required IPAddress RemoteAddress { get; init; }
    public required int RemotePort { get; init; }
    public required TcpConnectionState State { get; init; }

    /// <summary>
    /// Identity of this connection across samples. The four-tuple plus protocol is what the
    /// OS itself uses to keep sockets distinct, so two samples agreeing on it describe the
    /// same connection. PID is excluded: it cannot change for a live socket, and including
    /// it would split a flow if the table reported it inconsistently.
    /// </summary>
    public ConnectionKey Key => new(
        Protocol,
        LocalAddress.ToString(),
        LocalPort,
        RemoteAddress.ToString(),
        RemotePort);

    /// <summary>
    /// True when the OS reports no owning process. TCP sockets in TIME_WAIT outlive the
    /// process that opened them and are reported as PID 0, so a connection first seen in
    /// this state cannot be attributed to any application.
    ///
    /// A flow Keyhole was already tracking keeps the identity it was opened with, so this
    /// only affects connections that were already finished when monitoring started.
    /// </summary>
    public bool IsUnattributable => ProcessId == 0;

    /// <summary>
    /// A listening socket has no peer. These are not traffic and must not become flows,
    /// otherwise every server port would show up as an outbound connection to 0.0.0.0.
    /// </summary>
    public bool IsListener =>
        State == TcpConnectionState.Listen ||
        (RemotePort == 0 && Equals(RemoteAddress, AnyFor(RemoteAddress)));

    private static IPAddress AnyFor(IPAddress address) =>
        address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
            ? IPAddress.IPv6Any
            : IPAddress.Any;
}

public readonly record struct ConnectionKey(
    TransportProtocol Protocol,
    string LocalAddress,
    int LocalPort,
    string RemoteAddress,
    int RemotePort);
