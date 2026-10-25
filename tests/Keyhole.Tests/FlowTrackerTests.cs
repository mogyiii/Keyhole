using System.Net;
using Keyhole.Core.Monitoring;

namespace Keyhole.Tests;

/// <summary>
/// Drives the tracker with scripted snapshots so lifetime handling can be asserted
/// exactly, rather than against whatever the machine happens to be doing.
/// </summary>
public class FlowTrackerTests
{
    private static NetworkConnection Connection(
        int pid = 100,
        string remote = "93.184.216.34",
        int remotePort = 443,
        int localPort = 50000,
        TcpConnectionState state = TcpConnectionState.Established,
        TransportProtocol protocol = TransportProtocol.Tcp) => new()
        {
            ProcessId = pid,
            Protocol = protocol,
            LocalAddress = IPAddress.Parse("192.168.1.10"),
            LocalPort = localPort,
            RemoteAddress = IPAddress.Parse(remote),
            RemotePort = remotePort,
            State = state,
        };

    private static FlowTracker TrackerOver(FakeSocketReader reader) =>
        new(reader, new FakeProcessResolver(), new FakeHostnameResolver());

    [Fact]
    public void New_connection_is_reported_as_opened()
    {
        var reader = new FakeSocketReader();
        var tracker = TrackerOver(reader);

        reader.Connections = [Connection()];
        var result = tracker.Sample();

        Assert.Single(result.Opened);
        Assert.Empty(result.Closed);
        Assert.Equal(1, result.ActiveCount);
    }

    [Fact]
    public void Unchanged_connection_is_not_reported_twice()
    {
        var reader = new FakeSocketReader();
        var tracker = TrackerOver(reader);

        reader.Connections = [Connection()];
        tracker.Sample();
        var second = tracker.Sample();

        // Re-reporting would make every sample look like a burst of new activity.
        Assert.Empty(second.Opened);
        Assert.Empty(second.Closed);
        Assert.Equal(1, second.ActiveCount);
    }

    [Fact]
    public void Vanished_connection_is_reported_as_closed()
    {
        var reader = new FakeSocketReader();
        var tracker = TrackerOver(reader);

        reader.Connections = [Connection()];
        tracker.Sample();

        reader.Connections = [];
        var result = tracker.Sample();

        Assert.Single(result.Closed);
        Assert.Equal(0, result.ActiveCount);
        Assert.NotNull(result.Closed[0].EndedUtc);
        Assert.False(result.Closed[0].IsActive);
    }

    [Fact]
    public void Closed_connection_stays_visible_for_a_while()
    {
        var reader = new FakeSocketReader();
        var tracker = TrackerOver(reader);

        reader.Connections = [Connection()];
        tracker.Sample();
        reader.Connections = [];
        tracker.Sample();

        // Dropping it immediately would make short-lived connections impossible to see.
        var snapshot = tracker.Snapshot();
        Assert.Single(snapshot);
        Assert.False(snapshot[0].IsActive);
    }

    [Fact]
    public void Listeners_are_ignored()
    {
        var reader = new FakeSocketReader
        {
            Connections =
            [
                Connection(state: TcpConnectionState.Listen, remote: "0.0.0.0", remotePort: 0),
                Connection(localPort: 50001),
            ],
        };

        var tracker = TrackerOver(reader);
        var result = tracker.Sample();

        // A listening socket is not traffic; counting it would fill the app list with
        // every server port on the machine pointing at 0.0.0.0.
        Assert.Single(result.Opened);
        Assert.Equal(50001, result.Opened[0].Connection.LocalPort);
    }

    [Fact]
    public void Connection_first_seen_without_an_owner_is_ignored()
    {
        var reader = new FakeSocketReader
        {
            Connections =
            [
                // TIME_WAIT sockets outlive their process and report PID 0. Tracking them
                // would pile finished activity under "System Idle Process" and dominate
                // the app list — on a real machine this was 56 of 57 connections.
                Connection(pid: 0, state: TcpConnectionState.TimeWait, localPort: 50001),
                Connection(pid: 100, localPort: 50002),
            ],
        };

        var result = TrackerOver(reader).Sample();

        Assert.Single(result.Opened);
        Assert.Equal(100, result.Opened[0].Connection.ProcessId);
    }

    [Fact]
    public void Tracked_connection_keeps_its_owner_when_it_enters_time_wait()
    {
        var reader = new FakeSocketReader();
        var tracker = TrackerOver(reader);

        reader.Connections = [Connection(pid: 100)];
        tracker.Sample();

        // The OS reports PID 0 once the socket reaches TIME_WAIT. The flow must keep the
        // identity it was opened with rather than becoming unattributed.
        reader.Connections = [Connection(pid: 0, state: TcpConnectionState.TimeWait)];
        var second = tracker.Sample();

        Assert.Empty(second.Opened);
        Assert.Empty(second.Closed);

        var flow = tracker.Snapshot().Single();
        Assert.Equal(@"C:\app.exe", flow.Process.ExecutablePath);
        Assert.Equal(TcpConnectionState.TimeWait, flow.Connection.State);
    }

    [Fact]
    public void Same_endpoints_on_different_protocols_are_distinct_flows()
    {
        var reader = new FakeSocketReader
        {
            Connections =
            [
                Connection(protocol: TransportProtocol.Tcp),
                Connection(protocol: TransportProtocol.Udp),
            ],
        };

        var result = TrackerOver(reader).Sample();

        Assert.Equal(2, result.Opened.Count);
    }

    [Fact]
    public void Reopened_connection_after_close_counts_as_new()
    {
        var reader = new FakeSocketReader();
        var tracker = TrackerOver(reader);

        reader.Connections = [Connection()];
        tracker.Sample();

        reader.Connections = [];
        tracker.Sample();

        reader.Connections = [Connection()];
        var third = tracker.Sample();

        // The OS can reuse a local port. Treating the second appearance as a continuation
        // would merge two unrelated conversations into one flow.
        Assert.Single(third.Opened);
        Assert.Equal(1, third.ActiveCount);
    }

    [Fact]
    public void Hostname_arriving_late_is_picked_up_on_a_later_sample()
    {
        var reader = new FakeSocketReader { Connections = [Connection()] };
        var hostnames = new FakeHostnameResolver();
        var tracker = new FlowTracker(reader, new FakeProcessResolver(), hostnames);

        tracker.Sample();
        Assert.Null(tracker.Snapshot()[0].RemoteHostname);

        // DNS resolves in the background, so the name shows up on a later pass.
        hostnames.Names["93.184.216.34"] = "example.test";
        tracker.Sample();

        Assert.Equal("example.test", tracker.Snapshot()[0].RemoteHostname);
    }

    [Fact]
    public void Socket_read_failure_does_not_lose_existing_state()
    {
        var reader = new FakeSocketReader { Connections = [Connection()] };
        var tracker = TrackerOver(reader);
        tracker.Sample();

        reader.ThrowOnRead = true;
        var result = tracker.Sample();

        // A failed read must not look like "every connection closed at once".
        Assert.Empty(result.Closed);
        Assert.Single(tracker.Snapshot());
        Assert.True(tracker.Snapshot()[0].IsActive);
    }

    [Fact]
    public void App_activity_groups_processes_of_the_same_program()
    {
        var reader = new FakeSocketReader
        {
            Connections =
            [
                Connection(pid: 100, localPort: 50001),
                Connection(pid: 101, localPort: 50002),
                Connection(pid: 102, localPort: 50003),
            ],
        };

        var processes = new FakeProcessResolver();
        processes.Paths[100] = @"C:\Program Files\Browser\browser.exe";
        processes.Paths[101] = @"C:\Program Files\Browser\browser.exe";
        processes.Paths[102] = @"C:\Other\tool.exe";

        var tracker = new FlowTracker(reader, processes, new FakeHostnameResolver());
        tracker.Sample();

        var apps = tracker.GetAppActivity();

        // A browser with three helper processes is one entry to the user, not three.
        Assert.Equal(2, apps.Count);

        var browser = apps.Single(a => a.ExecutablePath!.EndsWith("browser.exe", StringComparison.Ordinal));
        Assert.Equal(2, browser.ActiveConnections);
        Assert.Equal([100, 101], browser.ProcessIds);
    }

    [Fact]
    public void App_activity_falls_back_to_address_when_hostname_is_unknown()
    {
        var reader = new FakeSocketReader { Connections = [Connection()] };
        var tracker = TrackerOver(reader);
        tracker.Sample();

        var app = tracker.GetAppActivity().Single();

        // Showing nothing while DNS is pending would be worse than showing the address.
        Assert.Equal(["93.184.216.34"], app.RecentRemoteHosts);
    }

    [Fact]
    public void Byte_counts_are_taken_from_the_counter_source()
    {
        var reader = new FakeSocketReader { Connections = [Connection()] };
        var bytes = new FakeByteCounter();
        var tracker = new FlowTracker(reader, new FakeProcessResolver(), new FakeHostnameResolver(), bytes);

        tracker.Sample();
        var key = tracker.Snapshot().Single().Key;

        bytes.Counts[key] = new ByteCounts(1000, 2000);
        tracker.Sample();

        var flow = tracker.Snapshot().Single();
        Assert.Equal(1000, flow.BytesSent);
        Assert.Equal(2000, flow.BytesReceived);
    }

    [Fact]
    public void Byte_counts_are_replaced_not_accumulated()
    {
        var reader = new FakeSocketReader { Connections = [Connection()] };
        var bytes = new FakeByteCounter();
        var tracker = new FlowTracker(reader, new FakeProcessResolver(), new FakeHostnameResolver(), bytes);

        tracker.Sample();
        var key = tracker.Snapshot().Single().Key;

        // ETW totals are cumulative. Adding them each sample would inflate every figure
        // quadratically over the life of a connection.
        bytes.Counts[key] = new ByteCounts(1000, 0);
        tracker.Sample();
        bytes.Counts[key] = new ByteCounts(1500, 0);
        tracker.Sample();

        Assert.Equal(1500, tracker.Snapshot().Single().BytesSent);
    }

    [Fact]
    public void Counts_survive_a_sample_where_the_source_reports_nothing()
    {
        var reader = new FakeSocketReader { Connections = [Connection()] };
        var bytes = new FakeByteCounter();
        var tracker = new FlowTracker(reader, new FakeProcessResolver(), new FakeHostnameResolver(), bytes);

        tracker.Sample();
        var key = tracker.Snapshot().Single().Key;

        bytes.Counts[key] = new ByteCounts(5000, 5000);
        tracker.Sample();

        // An ETW session that drops or restarts would otherwise reset a long-lived
        // connection's totals to zero mid-flight.
        bytes.Counts.Remove(key);
        tracker.Sample();

        Assert.Equal(5000, tracker.Snapshot().Single().BytesSent);
    }

    [Fact]
    public void Tracking_works_without_any_byte_counter()
    {
        var reader = new FakeSocketReader { Connections = [Connection()] };
        var tracker = new FlowTracker(
            reader, new FakeProcessResolver(), new FakeHostnameResolver(),
            new NullByteCounterSource("not elevated"));

        var result = tracker.Sample();

        // Unelevated, byte counting cannot start. Connection tracking must still work,
        // with zeroes rather than no data at all.
        Assert.Single(result.Opened);
        Assert.Equal(0, result.Opened[0].BytesSent);
    }

    private sealed class FakeByteCounter : IByteCounterSource
    {
        public Dictionary<ConnectionKey, ByteCounts> Counts { get; } = [];

        public bool IsRunning => true;
        public string? UnavailableReason => null;

        public ByteCounts GetCounts(ConnectionKey key) =>
            Counts.TryGetValue(key, out var counts) ? counts : ByteCounts.Zero;

        public IReadOnlyList<UdpPeer> GetUdpPeers(int localPort) => [];
    }

    private sealed class FakeSocketReader : ISocketTableReader
    {
        public IReadOnlyList<NetworkConnection> Connections { get; set; } = [];
        public bool ThrowOnRead { get; set; }

        public IReadOnlyList<NetworkConnection> ReadAll() =>
            ThrowOnRead ? throw new InvalidOperationException("simulated failure") : Connections;
    }

    private sealed class FakeProcessResolver : IProcessResolver
    {
        public Dictionary<int, string> Paths { get; } = [];

        public ProcessIdentity Resolve(int processId) => new()
        {
            ProcessId = processId,
            ExecutablePath = Paths.TryGetValue(processId, out var path) ? path : @"C:\app.exe",
            DisplayName = "app",
            Signature = SignatureStatus.Valid,
            StartTimeUtc = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc),
        };
    }

    private sealed class FakeHostnameResolver : IHostnameResolver
    {
        public Dictionary<string, string> Names { get; } = [];

        public string? TryGet(IPAddress address) =>
            Names.TryGetValue(address.ToString(), out var name) ? name : null;
    }
}
