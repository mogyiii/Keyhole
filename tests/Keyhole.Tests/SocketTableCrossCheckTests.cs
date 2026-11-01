using System.Net.NetworkInformation;
using Keyhole.Core.Monitoring;
using Keyhole.Native;
using Xunit.Abstractions;

namespace Keyhole.Tests;

/// <summary>
/// Cross-checks <see cref="SocketTableReader"/> against the BCL's own TCP enumeration.
/// Both read the same OS tables through independent code, so agreement is real evidence
/// that the P/Invoke marshalling is right — something a self-consistent test cannot show.
/// The BCL API reports no PID, which is exactly why Keyhole has its own reader.
///
/// Both tests read the BCL before <em>and</em> after Keyhole, and compare only against
/// what was present in both. The machine's socket table changes constantly — this suite
/// alone opens and closes dozens of sockets — so a single pair of snapshots disagrees for
/// reasons that have nothing to do with marshalling. Sandwiching removes the drift instead
/// of tolerating it, which both stops the flakiness and lets the assertion be exact rather
/// than "most of them matched".
/// </summary>
public class SocketTableCrossCheckTests(ITestOutputHelper output)
{
    [Fact]
    public void Established_connections_agree_with_the_BCL()
    {
        var before = BclEstablished();
        var fromKeyhole = KeyholeEstablished();
        var after = BclEstablished();

        // Present in both BCL reads, so it existed throughout the window in which Keyhole
        // took its own. Anything in here must be in Keyhole's set.
        var stable = before.Intersect(after).ToHashSet(StringComparer.OrdinalIgnoreCase);

        output.WriteLine(
            $"BCL before={before.Count} after={after.Count} stable={stable.Count}, " +
            $"Keyhole={fromKeyhole.Count}");

        var missing = stable.Except(fromKeyhole).ToList();

        foreach (var item in missing.Take(5))
        {
            output.WriteLine($"  stable in BCL but absent from Keyhole: {item}");
        }

        Assert.Empty(missing);
    }

    [Fact]
    public void Listener_ports_agree_with_the_BCL()
    {
        var before = BclListenerPorts();
        var fromKeyhole = KeyholeListenerPorts();
        var after = BclListenerPorts();

        var stable = before.Intersect(after).ToHashSet();

        output.WriteLine(
            $"BCL before={before.Count} after={after.Count} stable={stable.Count}, " +
            $"Keyhole={fromKeyhole.Count}");

        var missing = stable.Except(fromKeyhole).ToList();

        foreach (var port in missing.Take(10))
        {
            output.WriteLine($"  stable BCL listener port absent from Keyhole: {port}");
        }

        Assert.Empty(missing);
    }

    private static HashSet<string> BclEstablished() =>
        IPGlobalProperties.GetIPGlobalProperties()
            .GetActiveTcpConnections()
            .Where(c => c.State == TcpState.Established)
            .Select(c => NormaliseEndpointPair($"{c.LocalEndPoint}->{c.RemoteEndPoint}"))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

    private static HashSet<string> KeyholeEstablished() =>
        new SocketTableReader().ReadAll()
            .Where(c => c.Protocol == TransportProtocol.Tcp)
            .Where(c => c.State == TcpConnectionState.Established)
            .Select(c => NormaliseEndpointPair(
                $"{c.LocalAddress}:{c.LocalPort}->{c.RemoteAddress}:{c.RemotePort}"))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

    private static HashSet<int> BclListenerPorts() =>
        IPGlobalProperties.GetIPGlobalProperties()
            .GetActiveTcpListeners()
            .Select(e => e.Port)
            .ToHashSet();

    private static HashSet<int> KeyholeListenerPorts() =>
        new SocketTableReader().ReadAll()
            .Where(c => c.Protocol == TransportProtocol.Tcp && c.State == TcpConnectionState.Listen)
            .Select(c => c.LocalPort)
            .ToHashSet();

    /// <summary>
    /// The BCL renders IPv6 endpoints with brackets and may carry a scope id;
    /// strip both so the two sources are comparable.
    /// </summary>
    private static string NormaliseEndpointPair(string pair) =>
        string.Join("->", pair.Split("->").Select(NormaliseEndpoint));

    private static string NormaliseEndpoint(string endpoint)
    {
        endpoint = endpoint.Replace("[", "").Replace("]", "");

        var portIndex = endpoint.LastIndexOf(':');
        if (portIndex < 0)
        {
            return endpoint;
        }

        var host = endpoint[..portIndex];
        var port = endpoint[(portIndex + 1)..];

        var scopeIndex = host.IndexOf('%');
        if (scopeIndex >= 0)
        {
            host = host[..scopeIndex];
        }

        return $"{host}:{port}";
    }
}
