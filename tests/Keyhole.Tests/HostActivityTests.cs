using System.Net;
using Keyhole.Core.Monitoring;

namespace Keyhole.Tests;

/// <summary>
/// The per-destination view.
///
/// The grouping is the whole feature. A service behind a dozen CDN addresses has to read
/// as one destination, an address reverse DNS could not name has to keep its own row, and
/// the applications sharing a destination have to be counted — that last one is the thing
/// the tab exists to surface.
/// </summary>
public class HostActivityTests
{
    [Fact]
    public void Addresses_sharing_a_hostname_collapse_into_one_row()
    {
        // Anything behind a CDN answers at several addresses. Without grouping by name,
        // one service reads as a dozen anonymous destinations and the volume that should
        // rank it first is split a dozen ways.
        var tracker = Tracker(
            Flow("chrome.exe", "93.184.216.34", 443, "example.com", sent: 100, received: 1000),
            Flow("chrome.exe", "93.184.216.35", 443, "example.com", sent: 200, received: 2000),
            Flow("chrome.exe", "93.184.216.36", 443, "example.com", sent: 300, received: 3000));

        var host = Assert.Single(tracker.GetHostActivity());

        Assert.Equal("example.com", host.Host);
        Assert.Equal(600, host.BytesSent);
        Assert.Equal(6000, host.BytesReceived);
        Assert.Equal(3, host.TotalConnections);
        Assert.Equal(3, host.Addresses.Count);
    }

    [Fact]
    public void An_unresolved_address_keeps_its_own_row()
    {
        // Merging unnamed addresses under one bucket would hide exactly the rows worth
        // looking at: a destination nobody can name is more interesting than one that
        // resolves to a familiar CDN.
        var tracker = Tracker(
            Flow("app.exe", "203.0.113.1", 443, hostname: null, sent: 10, received: 10),
            Flow("app.exe", "203.0.113.2", 443, hostname: null, sent: 20, received: 20));

        var hosts = tracker.GetHostActivity();

        Assert.Equal(2, hosts.Count);
        Assert.Contains(hosts, h => h.Host == "203.0.113.1");
        Assert.Contains(hosts, h => h.Host == "203.0.113.2");
    }

    [Fact]
    public void Applications_sharing_a_destination_are_all_listed()
    {
        // The reason this view exists. Three unrelated programs reaching one host is
        // interesting in a way that none of the three looks interesting on its own.
        var tracker = Tracker(
            Flow("chrome.exe", "198.51.100.7", 443, "telemetry.example", sent: 1, received: 1),
            Flow("updater.exe", "198.51.100.7", 443, "telemetry.example", sent: 1, received: 1),
            Flow("game.exe", "198.51.100.7", 443, "telemetry.example", sent: 1, received: 1));

        var host = Assert.Single(tracker.GetHostActivity());

        Assert.Equal(3, host.Applications.Count);
        Assert.Contains("chrome.exe", host.Applications);
        Assert.Contains("updater.exe", host.Applications);
        Assert.Contains("game.exe", host.Applications);
    }

    [Fact]
    public void The_list_is_ranked_by_total_volume()
    {
        var tracker = Tracker(
            Flow("a.exe", "203.0.113.1", 443, "small.example", sent: 1, received: 1),
            Flow("a.exe", "203.0.113.2", 443, "big.example", sent: 5_000, received: 5_000),
            Flow("a.exe", "203.0.113.3", 443, "medium.example", sent: 100, received: 100));

        var hosts = tracker.GetHostActivity();

        // "Top hosts" is a question about volume, in both directions together: a host
        // Keyhole uploaded a lot to matters as much as one it downloaded from.
        Assert.Equal(
            ["big.example", "medium.example", "small.example"],
            hosts.Select(h => h.Host));
    }

    [Fact]
    public void Loopback_is_excluded()
    {
        // A machine talks to itself constantly. Those rows would crowd out every real
        // destination while saying nothing about what left the machine.
        var tracker = Tracker(
            Flow("a.exe", "127.0.0.1", 5432, hostname: null, sent: 10_000, received: 10_000),
            Flow("a.exe", "::1", 5432, hostname: null, sent: 10_000, received: 10_000),
            Flow("a.exe", "203.0.113.9", 443, "real.example", sent: 1, received: 1));

        var host = Assert.Single(tracker.GetHostActivity());

        Assert.Equal("real.example", host.Host);
    }

    [Fact]
    public void Ports_are_reported_so_a_web_host_is_distinguishable_from_a_mail_one()
    {
        var tracker = Tracker(
            Flow("a.exe", "203.0.113.1", 443, "mixed.example", sent: 1, received: 1),
            Flow("a.exe", "203.0.113.1", 993, "mixed.example", sent: 1, received: 1));

        var host = Assert.Single(tracker.GetHostActivity());

        Assert.Equal([443, 993], host.Ports);
    }

    /// <summary>
    /// A tracker fed one sample of the given connections. Byte totals come from a scripted
    /// counter, because the real one needs an elevated ETW session.
    /// </summary>
    private static FlowTracker Tracker(params ScriptedFlow[] scripted)
    {
        // A distinct local port per flow, assigned here rather than derived from the
        // remote endpoint: several flows to the same host and port are exactly what these
        // tests are about, and deriving the local port would collapse them onto one
        // connection key.
        var flows = scripted
            .Select((f, i) => f with { LocalPort = 50_000 + i })
            .ToArray();

        var sockets = new ScriptedSockets(flows);
        var tracker = new FlowTracker(
            sockets,
            new ScriptedProcesses(flows),
            new ScriptedHostnames(flows),
            new ScriptedBytes(flows));

        tracker.Sample();
        return tracker;
    }

    private static ScriptedFlow Flow(
        string process, string address, int port, string? hostname, long sent, long received) =>
        new(process, IPAddress.Parse(address), port, hostname, sent, received);

    internal sealed record ScriptedFlow(
        string Process,
        IPAddress Address,
        int Port,
        string? Hostname,
        long Sent,
        long Received)
    {
        /// <summary>Assigned by the factory, so every flow has its own connection key.</summary>
        public int LocalPort { get; init; } = 50_000;

        /// <summary>
        /// A stable pid per process name. Deliberately not GetHashCode: .NET randomises
        /// string hashes per run, which would make the scripted pids differ between runs.
        /// </summary>
        public int ProcessId => 100 + (Process.Sum(c => c) % 30_000);

        public NetworkConnection Connection => new()
        {
            ProcessId = ProcessId,
            Protocol = TransportProtocol.Tcp,
            LocalAddress = IPAddress.Parse("10.0.0.5"),
            LocalPort = LocalPort,
            RemoteAddress = Address,
            RemotePort = Port,
            State = TcpConnectionState.Established,
        };
    }

    private sealed class ScriptedSockets(ScriptedFlow[] flows) : ISocketTableReader
    {
        public IReadOnlyList<NetworkConnection> ReadAll() => [.. flows.Select(f => f.Connection)];
    }

    private sealed class ScriptedProcesses(ScriptedFlow[] flows) : IProcessResolver
    {
        public ProcessIdentity Resolve(int processId)
        {
            var flow = flows.FirstOrDefault(f => f.Connection.ProcessId == processId);

            return new ProcessIdentity
            {
                ProcessId = processId,
                DisplayName = flow?.Process ?? $"pid {processId}",
                ExecutablePath = flow is null ? null : $@"C:\apps\{flow.Process}",
                Signature = SignatureStatus.Unknown,
            };
        }
    }

    private sealed class ScriptedHostnames(ScriptedFlow[] flows) : IHostnameResolver
    {
        public string? TryGet(IPAddress address) =>
            flows.FirstOrDefault(f => f.Address.Equals(address))?.Hostname;
    }

    private sealed class ScriptedBytes(ScriptedFlow[] flows) : IByteCounterSource
    {
        public bool IsRunning => true;

        public string? UnavailableReason => null;

        /// <summary>The same answer as a code, for the interface to translate.</summary>
        public string? UnavailableCode => null;

        public ByteCounts GetCounts(ConnectionKey key)
        {
            var flow = flows.FirstOrDefault(f => f.Connection.Key.Equals(key));

            return flow is null ? ByteCounts.Zero : new ByteCounts(flow.Sent, flow.Received);
        }

        public IReadOnlyList<UdpPeer> GetUdpPeers(int processId, int localPort) => [];
    }
}
