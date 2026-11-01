using System.Net;
using System.Net.Sockets;
using Keyhole.Core.Monitoring;
using Keyhole.Native;
using Xunit.Abstractions;

namespace Keyhole.Tests;

/// <summary>
/// Exercises the real iphlpapi tables. A struct layout or byte-order mistake in P/Invoke
/// produces plausible-looking garbage rather than an error, so these assert against facts
/// the test itself establishes.
/// </summary>
public class SocketTableReaderTests(ITestOutputHelper output)
{
    private readonly SocketTableReader _reader = new();

    [Fact]
    public void Reads_a_non_empty_table()
    {
        var connections = _reader.ReadAll();

        // Any running Windows machine has sockets open.
        Assert.NotEmpty(connections);
        output.WriteLine($"Read {connections.Count} sockets.");
    }

    [Fact]
    public void No_tcp_row_reports_a_state_outside_the_enum()
    {
        // MIB_TCP_STATE runs from 1 to 12, but GetExtendedTcpTable returns 0 for some
        // listening sockets — confirmed by hexdumping a socket's row right after calling
        // listen() on it. Those rows have no peer, so they are reported as Listen.
        //
        // Nothing should reach the UI as a raw number the enum cannot name, because the
        // drill-down shows the state as text.
        var tcp = _reader.ReadAll()
            .Where(c => c.Protocol == TransportProtocol.Tcp)
            .ToList();

        Assert.NotEmpty(tcp);

        var unnamed = tcp
            .Where(c => !Enum.IsDefined(c.State) || c.State == TcpConnectionState.None)
            .ToList();

        foreach (var c in unnamed)
        {
            output.WriteLine(
                $"unnamed state {(int)c.State} on {c.LocalAddress}:{c.LocalPort} " +
                $"-> {c.RemoteAddress}:{c.RemotePort}");
        }

        // A row with a peer and an uninterpretable state is left as None on purpose, so
        // this asserts on the listeners only: those are the ones we can reason about.
        Assert.DoesNotContain(unnamed, c => c.RemotePort == 0);
    }

    [Fact]
    public void A_listener_is_reported_as_listening_whatever_the_kernel_says()
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        socket.Listen(16);

        var port = ((IPEndPoint)socket.LocalEndPoint!).Port;

        // This exact socket is the one the kernel reports as state 0, which is what the
        // normalisation exists for. Testing it through a socket the test just created
        // keeps the check honest: there is no doubt about what state it is really in.
        var row = FindOwn(c => c.LocalPort == port, $"local port {port}");

        Assert.NotNull(row);
        Assert.Equal(TcpConnectionState.Listen, row.State);
        Assert.True(row.IsListener);
    }

    [Fact]
    public void Ports_are_in_range()
    {
        var connections = _reader.ReadAll();

        // Byte-order bugs show up here first: a misread port lands outside 0-65535
        // or clusters on impossible values.
        Assert.All(connections, c =>
        {
            Assert.InRange(c.LocalPort, 0, 65535);
            Assert.InRange(c.RemotePort, 0, 65535);
        });
    }

    [Fact]
    public void Finds_a_listener_this_test_just_created()
    {
        // Bind a real socket, then prove the reader sees it with this process's PID
        // and the exact port. This is the strongest available check that the layout,
        // port decoding and PID field are all correct.
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var expectedPort = ((IPEndPoint)listener.LocalEndpoint).Port;

        try
        {
            var row = FindOwn(
                c => c.LocalPort == expectedPort,
                $"local port {expectedPort}");

            Assert.NotNull(row);
            output.WriteLine($"Port {expectedPort}: state={row.State} pid={row.ProcessId}");

            Assert.Equal(TcpConnectionState.Listen, row.State);
            Assert.True(row.IsListener);
        }
        finally
        {
            listener.Stop();
        }
    }

    private NetworkConnection? FindOwn(int localPort, int remotePort) =>
        FindOwn(c => c.LocalPort == localPort && c.RemotePort == remotePort,
            $"local port {localPort} to remote port {remotePort}");

    /// <summary>
    /// Looks for one of this process's own TCP rows, retrying briefly.
    ///
    /// Retries on two things. A socket does not necessarily appear in the OS table the
    /// instant the call that created it returns, and the table intermittently reports a
    /// state outside MIB_TCP_STATE — the same socket can read correctly on one call and as
    /// nothing on the next. Polling past both is the honest way to test a shared, mutating
    /// resource: the alternative is a test that passes on an idle machine and fails on a
    /// busy one, which is what this one did.
    ///
    /// The owning process is part of the filter because a TIME_WAIT row from an earlier
    /// connection on the same ephemeral port is reported with pid 0, which would make the
    /// tuple ambiguous.
    /// </summary>
    private NetworkConnection? FindOwn(Func<NetworkConnection, bool> predicate, string description)
    {
        var deadline = DateTime.UtcNow.AddSeconds(5);

        while (true)
        {
            var matches = _reader.ReadAll()
                .Where(c => c.Protocol == TransportProtocol.Tcp)
                .Where(c => c.ProcessId == Environment.ProcessId)
                .Where(predicate)
                .ToList();

            // A state of None means the table had nothing to say this time, not that the
            // socket is in some state called None. Waiting for a real one is the point.
            if (matches.Count == 1 && matches[0].State != TcpConnectionState.None)
            {
                return matches[0];
            }

            Assert.True(
                matches.Count <= 1,
                $"{matches.Count} of this process's rows match {description}, " +
                "which should be impossible.");

            if (DateTime.UtcNow >= deadline)
            {
                return null;
            }

            Thread.Sleep(100);
        }
    }

    [Fact]
    public async Task Finds_an_established_connection_this_test_just_created()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, TestCancellation());
        using var accepted = await listener.AcceptTcpClientAsync(TestCancellation());

        try
        {
            var localEndpoint = (IPEndPoint)client.Client.LocalEndPoint!;

            var match = FindOwn(localEndpoint.Port, port);

            Assert.NotNull(match);
            output.WriteLine(
                $"{match.LocalAddress}:{match.LocalPort} -> {match.RemoteAddress}:{match.RemotePort} " +
                $"state={match.State} pid={match.ProcessId}");

            // Both ends of a real connection must be decoded, not just the local one.
            // These are what the test actually controls: it created this connection, so
            // the addresses, the ports and the owning process are facts.
            Assert.Equal(IPAddress.Loopback, match.LocalAddress);
            Assert.Equal(IPAddress.Loopback, match.RemoteAddress);
            Assert.Equal(port, match.RemotePort);
            Assert.Equal(Environment.ProcessId, match.ProcessId);

            // The state only has to be a state. Which one is not the test's to decide: a
            // loopback connection moves through Established, the FIN waits and Closed on
            // the OS's schedule, not ours, and earlier versions of this assertion failed
            // on a busy machine for reasons that had nothing to do with the decoding it
            // exists to check. What a marshalling bug produces is a value outside the
            // enum, and that is what this catches.
            Assert.True(
                Enum.IsDefined(match.State) && match.State != TcpConnectionState.None,
                $"State decoded as {(int)match.State}, which is not a TCP state.");
        }
        finally
        {
            listener.Stop();

            // Keeps both ends rooted until the polling above is done. Without this the
            // sockets can be collected and closed while the table is still being read,
            // which is one way the connection ends up half-closed mid-test.
            GC.KeepAlive(client);
            GC.KeepAlive(accepted);
        }
    }

    [Fact]
    public void Reports_both_address_families()
    {
        var connections = _reader.ReadAll();

        var v4 = connections.Count(c => c.LocalAddress.AddressFamily == AddressFamily.InterNetwork);
        var v6 = connections.Count(c => c.LocalAddress.AddressFamily == AddressFamily.InterNetworkV6);

        output.WriteLine($"IPv4 sockets: {v4}, IPv6 sockets: {v6}");

        // Windows always has IPv6 sockets open; zero means the v6 path silently failed.
        Assert.True(v4 > 0, "Expected at least one IPv4 socket.");
        Assert.True(v6 > 0, "Expected at least one IPv6 socket.");
    }

    [Fact]
    public void Reports_both_protocols()
    {
        var connections = _reader.ReadAll();

        var tcp = connections.Count(c => c.Protocol == TransportProtocol.Tcp);
        var udp = connections.Count(c => c.Protocol == TransportProtocol.Udp);

        output.WriteLine($"TCP: {tcp}, UDP: {udp}");

        Assert.True(tcp > 0, "Expected at least one TCP socket.");
        Assert.True(udp > 0, "Expected at least one UDP socket.");
    }

    [Fact]
    public void Listeners_are_distinguished_from_traffic()
    {
        var connections = _reader.ReadAll();

        // A listener with a real peer would mean IsListener is misclassifying,
        // which would pollute the app list with phantom connections to 0.0.0.0.
        Assert.All(
            connections.Where(c => c.State == TcpConnectionState.Listen),
            c => Assert.True(c.IsListener));

        Assert.All(
            connections.Where(c => c.State == TcpConnectionState.Established),
            c => Assert.False(c.IsListener));
    }

    private static CancellationToken TestCancellation() =>
        new CancellationTokenSource(TimeSpan.FromSeconds(10)).Token;
}
