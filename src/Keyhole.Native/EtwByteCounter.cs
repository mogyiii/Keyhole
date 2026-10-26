using System.Collections.Concurrent;
using System.Net;
using System.Security.Principal;
using Keyhole.Core.Monitoring;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Keyhole.Native;

/// <summary>
/// Counts bytes per connection from the kernel network ETW provider.
///
/// Runs its own real-time session on a background thread. Requires administrator rights:
/// without them the session cannot be created and the counter reports itself unavailable
/// rather than silently returning zeros that look like real measurements.
/// </summary>
public sealed class EtwByteCounter : IByteCounterSource, IDisposable
{
    private const string SessionName = "Keyhole-Network";

    private readonly ILogger _logger;
    private readonly ConcurrentDictionary<ConnectionKey, Counters> _tcp = new();
    private readonly ConcurrentDictionary<UdpKey, Counters> _udp = new();

    private TraceEventSession? _session;
    private Thread? _pump;

    public EtwByteCounter(ILogger<EtwByteCounter>? logger = null) =>
        _logger = logger ?? NullLogger<EtwByteCounter>.Instance;

    public bool IsRunning { get; private set; }

    public string? UnavailableReason { get; private set; }

    /// <summary>
    /// Starts the trace session. Returns false and sets <see cref="UnavailableReason"/>
    /// instead of throwing: monitoring must still work without byte counts.
    /// </summary>
    public bool TryStart()
    {
        if (IsRunning)
        {
            return true;
        }

        if (!IsElevated())
        {
            UnavailableReason = "Byte counting needs administrator rights; the service is not elevated.";
            _logger.LogWarning("{Reason}", UnavailableReason);
            return false;
        }

        try
        {
            // A session from a previous run that crashed would still be alive in the
            // kernel; TraceEventSession reuses the name and takes it over.
            _session = new TraceEventSession(SessionName) { StopOnDispose = true };

            _session.EnableKernelProvider(
                KernelTraceEventParser.Keywords.NetworkTCPIP);

            _session.Source.Kernel.TcpIpSend += OnTcpSend;
            _session.Source.Kernel.TcpIpRecv += OnTcpReceive;
            _session.Source.Kernel.TcpIpSendIPV6 += OnTcpSendV6;
            _session.Source.Kernel.TcpIpRecvIPV6 += OnTcpReceiveV6;
            _session.Source.Kernel.UdpIpSend += OnUdpSend;
            _session.Source.Kernel.UdpIpRecv += OnUdpReceive;

            // Process() blocks for the life of the session, so it needs its own thread.
            _pump = new Thread(() =>
            {
                try
                {
                    _session.Source.Process();
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "ETW pump stopped unexpectedly.");
                    IsRunning = false;
                    UnavailableReason = "The trace session stopped unexpectedly. See the service log.";
                }
            })
            {
                IsBackground = true,
                Name = "Keyhole ETW pump",
            };

            _pump.Start();

            IsRunning = true;
            UnavailableReason = null;
            _logger.LogInformation("ETW byte counting started on session '{Session}'.", SessionName);
            return true;
        }
        catch (UnauthorizedAccessException ex)
        {
            UnavailableReason = "Access denied creating the ETW session; administrator rights are required.";
            _logger.LogWarning(ex, "{Reason}", UnavailableReason);
        }
        catch (Exception ex)
        {
            UnavailableReason = $"Could not start the ETW session: {ex.Message}";
            _logger.LogError(ex, "Failed to start ETW byte counting.");
        }

        Cleanup();
        return false;
    }

    public ByteCounts GetCounts(ConnectionKey key) =>
        _tcp.TryGetValue(Canonical(key), out var counters)
            ? new ByteCounts(Interlocked.Read(ref counters.Sent), Interlocked.Read(ref counters.Received))
            : ByteCounts.Zero;

    /// <summary>
    /// Orders a connection's two endpoints deterministically.
    ///
    /// The kernel provider labels a receive event's endpoints the opposite way round from a
    /// send on the same connection, so keying on the fields as given files the two
    /// directions under different keys. Lookups only ever use one of them, which recorded
    /// every download as zero while uploads looked fine. Ordering the pair makes both
    /// directions land on one key without needing to know which field the provider calls
    /// local.
    ///
    /// Two sockets with exactly mirrored endpoints would share a key. That requires both
    /// ends on this machine, so it is confined to loopback.
    /// </summary>
    /// <summary>Exposes the ordering to tests; it is the whole correctness argument here.</summary>
    internal static ConnectionKey CanonicalForTests(ConnectionKey key) => Canonical(key);

    private static ConnectionKey Canonical(ConnectionKey key) =>
        Canonical(key.LocalAddress, key.LocalPort, key.RemoteAddress, key.RemotePort);

    private static ConnectionKey Canonical(string a, int aPort, string b, int bPort) =>
        string.CompareOrdinal($"{a}:{aPort}", $"{b}:{bPort}") <= 0
            ? new ConnectionKey(TransportProtocol.Tcp, a, aPort, b, bPort)
            : new ConnectionKey(TransportProtocol.Tcp, b, bPort, a, aPort);

    public IReadOnlyList<UdpPeer> GetUdpPeers(int processId, int localPort) =>
        _udp
            .Where(pair => pair.Key.ProcessId == processId && pair.Key.LocalPort == localPort)
            .Select(pair => new UdpPeer(
                pair.Key.RemoteAddress,
                pair.Key.RemotePort,
                Interlocked.Read(ref pair.Value.Sent),
                Interlocked.Read(ref pair.Value.Received)))
            .OrderByDescending(p => p.Sent + p.Received)
            .ToList();

    /// <summary>
    /// Per-event-type counts. Distinguishes "the provider never sent us this event" from
    /// "we received it and filed it under a key nobody reads" — two failures that look
    /// identical from outside and need opposite fixes.
    /// </summary>
    private long _tcpSendEvents;
    private long _tcpRecvEvents;
    private long _udpSendEvents;
    private long _udpRecvEvents;

    private int _loggedRecvSample;

    public string EventCounts =>
        $"tcpSend={Interlocked.Read(ref _tcpSendEvents)} tcpRecv={Interlocked.Read(ref _tcpRecvEvents)} " +
        $"udpSend={Interlocked.Read(ref _udpSendEvents)} udpRecv={Interlocked.Read(ref _udpRecvEvents)}";

    private void OnTcpSend(TcpIpSendTraceData data)
    {
        Interlocked.Increment(ref _tcpSendEvents);
        AddTcp(data.saddr, data.sport, data.daddr, data.dport, data.size, sent: true);
    }

    private void OnTcpReceive(TcpIpTraceData data)
    {
        Interlocked.Increment(ref _tcpRecvEvents);

        // Log one sample's raw fields. Which endpoint the provider calls source on a
        // receive decides whether these bytes land on the same key as the matching sends,
        // and getting it backwards silently records every download as zero.
        if (Interlocked.Exchange(ref _loggedRecvSample, 1) == 0)
        {
            _logger.LogInformation(
                "First TCP recv event: saddr={Saddr}:{Sport} daddr={Daddr}:{Dport} size={Size} pid={Pid}",
                data.saddr, data.sport, data.daddr, data.dport, data.size, data.ProcessID);
        }

        AddTcp(data.saddr, data.sport, data.daddr, data.dport, data.size, sent: false);
    }

    private void OnTcpSendV6(TcpIpV6SendTraceData data) =>
        AddTcp(data.saddr, data.sport, data.daddr, data.dport, data.size, sent: true);

    private void OnTcpReceiveV6(TcpIpV6TraceData data) =>
        AddTcp(data.saddr, data.sport, data.daddr, data.dport, data.size, sent: false);

    /// <summary>
    /// Folds both directions of a connection onto one pair of totals. The endpoints are
    /// ordered rather than taken as given, because the provider labels them differently
    /// for sends and receives; see <see cref="Canonical(string, int, string, int)"/>.
    /// </summary>
    private void AddTcp(IPAddress source, int sourcePort, IPAddress dest, int destPort, int size, bool sent)
    {
        var key = Canonical(source.ToString(), sourcePort, dest.ToString(), destPort);
        var counters = _tcp.GetOrAdd(key, static _ => new Counters());

        if (sent)
        {
            Interlocked.Add(ref counters.Sent, size);
        }
        else
        {
            Interlocked.Add(ref counters.Received, size);
        }
    }

    // ETW carries the owning process on the event itself, which is the only place a UDP
    // datagram's sender is recorded: the UDP socket table has no peer column at all.
    private void OnUdpSend(UdpIpTraceData data)
    {
        Interlocked.Increment(ref _udpSendEvents);
        AddUdp(data.ProcessID, data.sport, data.daddr, data.dport, data.size, sent: true);
    }

    private void OnUdpReceive(UdpIpTraceData data)
    {
        Interlocked.Increment(ref _udpRecvEvents);
        AddUdp(data.ProcessID, data.dport, data.saddr, data.sport, data.size, sent: false);
    }

    private void AddUdp(int processId, int localPort, IPAddress remote, int remotePort, int size, bool sent)
    {
        var key = new UdpKey(processId, localPort, remote.ToString(), remotePort);
        var counters = _udp.GetOrAdd(key, static _ => new Counters());

        if (sent)
        {
            Interlocked.Add(ref counters.Sent, size);
        }
        else
        {
            Interlocked.Add(ref counters.Received, size);
        }
    }

    public void Dispose() => Cleanup();

    private void Cleanup()
    {
        IsRunning = false;

        try
        {
            _session?.Dispose();
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Disposing the ETW session threw.");
        }

        _session = null;

        // The pump thread exits once the session is disposed; it is a background thread,
        // so a stuck join must never hold up service shutdown.
        if (_pump is { IsAlive: true } && !_pump.Join(TimeSpan.FromSeconds(2)))
        {
            _logger.LogDebug("ETW pump thread did not exit within 2s; leaving it to the runtime.");
        }

        _pump = null;
    }

    private static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    /// <summary>Mutable so the counters can be updated with Interlocked in place.</summary>
    private sealed class Counters
    {
        public long Sent;
        public long Received;
    }

    private readonly record struct UdpKey(
        int ProcessId, int LocalPort, string RemoteAddress, int RemotePort);
}
