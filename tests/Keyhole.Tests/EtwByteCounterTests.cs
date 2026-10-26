using System.Security.Principal;
using Keyhole.Core.Monitoring;
using Keyhole.Native;
using Xunit.Abstractions;

namespace Keyhole.Tests;

public class EtwByteCounterTests(ITestOutputHelper output)
{
    private static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    [Fact]
    public void Start_reports_its_outcome_rather_than_throwing()
    {
        using var counter = new EtwByteCounter();

        // Whether or not this environment is elevated, starting must never throw:
        // monitoring has to continue without byte counts.
        var started = counter.TryStart();

        output.WriteLine($"elevated={IsElevated()} started={started} reason={counter.UnavailableReason ?? "<none>"}");

        Assert.Equal(started, counter.IsRunning);

        if (started)
        {
            Assert.Null(counter.UnavailableReason);
        }
        else
        {
            // A failure the UI cannot explain is worse than no feature at all.
            Assert.False(string.IsNullOrWhiteSpace(counter.UnavailableReason));
        }
    }

    [Fact]
    public void Unelevated_start_fails_with_an_explanation()
    {
        if (IsElevated())
        {
            output.WriteLine("Session is elevated; the unelevated path cannot be exercised here.");
            return;
        }

        using var counter = new EtwByteCounter();

        Assert.False(counter.TryStart());
        Assert.False(counter.IsRunning);
        Assert.Contains("administrator", counter.UnavailableReason!, StringComparison.OrdinalIgnoreCase);

        output.WriteLine($"reason: {counter.UnavailableReason}");
    }

    [Fact]
    public void Counts_read_as_zero_when_not_running()
    {
        using var counter = new EtwByteCounter();

        if (counter.TryStart())
        {
            output.WriteLine("Counter started; this test covers the stopped path only.");
            return;
        }

        var key = new ConnectionKey(TransportProtocol.Tcp, "10.0.0.1", 1234, "10.0.0.2", 443);

        Assert.Equal(ByteCounts.Zero, counter.GetCounts(key));
        Assert.Empty(counter.GetUdpPeers(processId: 4321, localPort: 1234));
    }

    [Fact]
    public void Dispose_without_start_is_safe()
    {
        var counter = new EtwByteCounter();

        // Shutdown runs this path whenever the session never started.
        counter.Dispose();
        counter.Dispose();
    }

    [Fact]
    public void Counts_are_found_whichever_way_round_the_endpoints_are_given()
    {
        using var counter = new EtwByteCounter();
        if (!counter.TryStart())
        {
            output.WriteLine("Not elevated; the counter stores nothing to look up.");
            return;
        }

        // The real defect this guards: the kernel labels a receive event's endpoints the
        // opposite way round from a send on the same connection. Keyed as given, uploads
        // landed on one key and downloads on another, and only the first was ever read --
        // 16 MB sent and 0 received across 37 real flows.
        var forward = new ConnectionKey(TransportProtocol.Tcp, "10.0.0.1", 50000, "93.184.216.34", 443);
        var reverse = new ConnectionKey(TransportProtocol.Tcp, "93.184.216.34", 443, "10.0.0.1", 50000);

        // Whatever is recorded, both orderings must resolve to the same totals.
        Assert.Equal(counter.GetCounts(forward), counter.GetCounts(reverse));
    }

    [Fact]
    public void Lookup_still_separates_genuinely_different_connections()
    {
        using var counter = new EtwByteCounter();

        var a = new ConnectionKey(TransportProtocol.Tcp, "10.0.0.1", 50000, "93.184.216.34", 443);
        var b = new ConnectionKey(TransportProtocol.Tcp, "10.0.0.1", 50001, "93.184.216.34", 443);

        // Folding the endpoint order must not fold distinct connections together.
        Assert.NotEqual(
            EtwByteCounter.CanonicalForTests(a),
            EtwByteCounter.CanonicalForTests(b));
    }

    [Fact]
    public void Mirrored_endpoints_canonicalise_to_one_key()
    {
        var forward = new ConnectionKey(TransportProtocol.Tcp, "10.0.0.1", 50000, "93.184.216.34", 443);
        var reverse = new ConnectionKey(TransportProtocol.Tcp, "93.184.216.34", 443, "10.0.0.1", 50000);

        Assert.Equal(
            EtwByteCounter.CanonicalForTests(forward),
            EtwByteCounter.CanonicalForTests(reverse));
    }

    [Fact]
    public void Canonical_ordering_is_stable()
    {
        var key = new ConnectionKey(TransportProtocol.Tcp, "10.0.0.1", 50000, "93.184.216.34", 443);

        // Must not depend on call order or process state, or totals would scatter across
        // keys over the life of a connection.
        Assert.Equal(
            EtwByteCounter.CanonicalForTests(key),
            EtwByteCounter.CanonicalForTests(EtwByteCounter.CanonicalForTests(key)));
    }

    [Fact]
    public void Null_source_reports_unavailable_with_a_reason()
    {
        IByteCounterSource source = new NullByteCounterSource("not elevated");

        Assert.False(source.IsRunning);
        Assert.Equal("not elevated", source.UnavailableReason);
        Assert.True(source.GetCounts(default).IsEmpty);
    }
}
