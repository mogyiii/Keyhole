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
/// </summary>
public class SocketTableCrossCheckTests(ITestOutputHelper output)
{
    [Fact]
    public void Established_connections_agree_with_the_BCL()
    {
        var properties = IPGlobalProperties.GetIPGlobalProperties();

        var fromBcl = properties.GetActiveTcpConnections()
            .Where(c => c.State == TcpState.Established)
            .Select(c => $"{c.LocalEndPoint}->{c.RemoteEndPoint}")
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var fromKeyhole = new SocketTableReader().ReadAll()
            .Where(c => c.Protocol == TransportProtocol.Tcp)
            .Where(c => c.State == TcpConnectionState.Established)
            .Select(c => $"{c.LocalAddress}:{c.LocalPort}->{c.RemoteAddress}:{c.RemotePort}")
            .Select(NormaliseEndpointPair)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var bclNormalised = fromBcl.Select(NormaliseEndpointPair).ToHashSet(StringComparer.OrdinalIgnoreCase);

        output.WriteLine($"BCL: {bclNormalised.Count}, Keyhole: {fromKeyhole.Count}");

        var missing = bclNormalised.Except(fromKeyhole).ToList();
        var extra = fromKeyhole.Except(bclNormalised).ToList();

        foreach (var item in missing.Take(5))
        {
            output.WriteLine($"  only in BCL:     {item}");
        }

        foreach (var item in extra.Take(5))
        {
            output.WriteLine($"  only in Keyhole: {item}");
        }

        // The two snapshots are taken moments apart, so a connection may legitimately
        // appear or vanish between them. Allow small drift, but the bulk must match:
        // a marshalling bug would make the overlap near zero, not merely imperfect.
        var overlap = bclNormalised.Intersect(fromKeyhole).Count();
        var expected = Math.Max(bclNormalised.Count, 1);

        Assert.True(
            overlap >= expected * 0.8,
            $"Only {overlap} of {bclNormalised.Count} BCL connections matched. " +
            $"Missing: {string.Join(", ", missing.Take(3))}");
    }

    [Fact]
    public void Listener_ports_agree_with_the_BCL()
    {
        var properties = IPGlobalProperties.GetIPGlobalProperties();

        var bclPorts = properties.GetActiveTcpListeners().Select(e => e.Port).ToHashSet();

        var keyholePorts = new SocketTableReader().ReadAll()
            .Where(c => c.Protocol == TransportProtocol.Tcp && c.State == TcpConnectionState.Listen)
            .Select(c => c.LocalPort)
            .ToHashSet();

        output.WriteLine($"BCL listener ports: {bclPorts.Count}, Keyhole: {keyholePorts.Count}");

        var overlap = bclPorts.Intersect(keyholePorts).Count();
        Assert.True(
            overlap >= Math.Max(bclPorts.Count, 1) * 0.8,
            $"Only {overlap} of {bclPorts.Count} listener ports matched.");
    }

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
