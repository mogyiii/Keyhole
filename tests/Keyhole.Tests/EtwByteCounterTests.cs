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
        Assert.Empty(counter.GetUdpPeers(1234));
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
    public void Null_source_reports_unavailable_with_a_reason()
    {
        IByteCounterSource source = new NullByteCounterSource("not elevated");

        Assert.False(source.IsRunning);
        Assert.Equal("not elevated", source.UnavailableReason);
        Assert.True(source.GetCounts(default).IsEmpty);
    }
}
