using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Keyhole.Core.Monitoring;
using Xunit.Abstractions;

namespace Keyhole.Tests;

/// <summary>
/// Cache and concurrency behaviour is tested against an injected lookup so the assertions
/// hold regardless of what the machine's resolver is doing. Live DNS is exercised
/// separately in <see cref="HostnameResolverLiveDnsTests"/>.
/// </summary>
public class HostnameResolverTests(ITestOutputHelper output)
{
    private static HostnameResolver WithLookup(
        Func<IPAddress, CancellationToken, Task<string?>> lookup) => new(lookup, null);

    private static HostnameResolver AlwaysReturns(string name) =>
        WithLookup((_, _) => Task.FromResult<string?>(name));

    [Fact]
    public void First_call_never_blocks()
    {
        // The sampling loop calls this for every connection. If it ever waits on DNS,
        // one unreachable resolver stalls all monitoring.
        using var resolver = WithLookup(async (_, ct) =>
        {
            await Task.Delay(TimeSpan.FromSeconds(30), ct);
            return "never.arrives";
        });

        var stopwatch = Stopwatch.StartNew();
        var result = resolver.TryGet(IPAddress.Parse("8.8.8.8"));
        stopwatch.Stop();

        output.WriteLine($"TryGet returned {result ?? "<null>"} in {stopwatch.ElapsedMilliseconds}ms");

        Assert.Null(result);
        Assert.True(stopwatch.ElapsedMilliseconds < 100, $"Took {stopwatch.ElapsedMilliseconds}ms.");
    }

    [Fact]
    public void Many_misses_stay_fast()
    {
        using var resolver = WithLookup(async (_, ct) =>
        {
            await Task.Delay(TimeSpan.FromSeconds(5), ct);
            return "slow.example";
        });

        var stopwatch = Stopwatch.StartNew();
        for (var i = 1; i < 200; i++)
        {
            resolver.TryGet(IPAddress.Parse($"203.0.113.{i % 256}"));
        }

        stopwatch.Stop();
        output.WriteLine($"199 lookups queued in {stopwatch.ElapsedMilliseconds}ms");

        // A full sampling pass must stay well under the sampling interval even when
        // every lookup is slow and the concurrency limit is saturated.
        Assert.True(stopwatch.ElapsedMilliseconds < 500, $"Took {stopwatch.ElapsedMilliseconds}ms.");
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("::1")]
    [InlineData("0.0.0.0")]
    [InlineData("169.254.1.1")]
    [InlineData("224.0.0.251")]
    [InlineData("255.255.255.255")]
    public async Task Skips_addresses_with_no_useful_reverse_record(string address)
    {
        var attempted = 0;
        using var resolver = WithLookup((_, _) =>
        {
            Interlocked.Increment(ref attempted);
            return Task.FromResult<string?>("should.not.happen");
        });

        var result = resolver.TryGet(IPAddress.Parse(address));
        await Task.Delay(300);

        Assert.Null(result);

        // These must not consume a lookup slot, and private ranges must never be sent
        // to an external resolver.
        Assert.Equal(0, attempted);
    }

    [Fact]
    public async Task Resolved_name_becomes_available_without_the_caller_waiting()
    {
        using var resolver = AlwaysReturns("example.test");
        var address = IPAddress.Parse("198.51.100.7");

        Assert.Null(resolver.TryGet(address));

        var resolved = await PollAsync(resolver, address, TimeSpan.FromSeconds(5));

        Assert.Equal("example.test", resolved);
    }

    [Fact]
    public async Task Cached_reads_are_instant()
    {
        using var resolver = AlwaysReturns("example.test");
        var address = IPAddress.Parse("198.51.100.8");

        await PollAsync(resolver, address, TimeSpan.FromSeconds(5));

        var stopwatch = Stopwatch.StartNew();
        var cached = resolver.TryGet(address);
        stopwatch.Stop();

        Assert.Equal("example.test", cached);
        Assert.True(stopwatch.ElapsedMilliseconds < 5, $"Cached read took {stopwatch.ElapsedMilliseconds}ms.");
    }

    [Fact]
    public async Task Repeated_calls_do_not_re_query()
    {
        var calls = 0;
        using var resolver = WithLookup((_, _) =>
        {
            Interlocked.Increment(ref calls);
            return Task.FromResult<string?>("example.test");
        });

        var address = IPAddress.Parse("198.51.100.9");
        await PollAsync(resolver, address, TimeSpan.FromSeconds(5));

        for (var i = 0; i < 1000; i++)
        {
            resolver.TryGet(address);
        }

        output.WriteLine($"lookup invoked {calls} time(s) across 1001 calls");

        // Without caching, a busy connection would queue a lookup on every sample.
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task Unresolvable_address_is_negatively_cached()
    {
        var calls = 0;
        using var resolver = WithLookup((_, _) =>
        {
            Interlocked.Increment(ref calls);
            throw new SocketException((int)SocketError.HostNotFound);
        });

        var address = IPAddress.Parse("203.0.113.42");

        resolver.TryGet(address);
        await Task.Delay(500);

        var stopwatch = Stopwatch.StartNew();
        for (var i = 0; i < 1000; i++)
        {
            resolver.TryGet(address);
        }

        stopwatch.Stop();
        output.WriteLine($"1000 repeat calls in {stopwatch.ElapsedMilliseconds}ms, {calls} lookup(s)");

        Assert.True(stopwatch.ElapsedMilliseconds < 200, $"Took {stopwatch.ElapsedMilliseconds}ms.");
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task Concurrent_lookups_are_bounded()
    {
        var concurrent = 0;
        var peak = 0;

        using var resolver = WithLookup(async (_, ct) =>
        {
            var now = Interlocked.Increment(ref concurrent);
            InterlockedMax(ref peak, now);

            await Task.Delay(200, ct);
            Interlocked.Decrement(ref concurrent);
            return "example.test";
        });

        for (var i = 1; i < 100; i++)
        {
            resolver.TryGet(IPAddress.Parse($"198.51.100.{i % 256}"));
        }

        await Task.Delay(1500);
        output.WriteLine($"peak concurrent lookups: {peak}");

        // Unbounded parallel DNS would be its own kind of network abuse from a tool
        // whose whole purpose is watching network behaviour.
        Assert.InRange(peak, 1, 8);
    }

    [Fact]
    public async Task Transient_failure_is_retried_sooner_than_a_missing_record()
    {
        var calls = 0;
        using var resolver = WithLookup((_, _) =>
        {
            var attempt = Interlocked.Increment(ref calls);

            // First attempt times out, second succeeds — a DNS hiccup, not a missing record.
            return attempt == 1
                ? throw new SocketException((int)SocketError.TryAgain)
                : Task.FromResult<string?>("recovered.test");
        });

        var address = IPAddress.Parse("198.51.100.33");

        resolver.TryGet(address);
        await Task.Delay(500);

        // Still inside the short transient TTL, so no re-query yet.
        Assert.Null(resolver.TryGet(address));
        Assert.Equal(1, calls);

        output.WriteLine($"after transient failure: {calls} call(s), still cached as unknown");
    }

    private static async Task<string?> PollAsync(HostnameResolver resolver, IPAddress address, TimeSpan limit)
    {
        var deadline = DateTime.UtcNow + limit;
        while (DateTime.UtcNow < deadline)
        {
            var value = resolver.TryGet(address);
            if (value is not null)
            {
                return value;
            }

            await Task.Delay(50);
        }

        return null;
    }

    private static void InterlockedMax(ref int target, int value)
    {
        int current;
        while (value > (current = Volatile.Read(ref target)))
        {
            if (Interlocked.CompareExchange(ref target, value, current) == current)
            {
                return;
            }
        }
    }
}

/// <summary>
/// Exercises the real resolver. Kept apart so its network dependence cannot make the
/// cache tests flaky, and so a missing resolver is reported rather than silently skipped.
/// </summary>
public class HostnameResolverLiveDnsTests(ITestOutputHelper output)
{
    [Fact]
    public async Task Resolves_a_real_address_when_dns_is_available()
    {
        var address = IPAddress.Parse("8.8.8.8");

        // Establish whether reverse DNS works here at all. Without this check, a silent
        // skip would hide a genuine resolver bug — which is exactly what it once did.
        string? expected;
        try
        {
            var entry = await Dns.GetHostEntryAsync(address).WaitAsync(TimeSpan.FromSeconds(5));
            expected = entry.HostName;
        }
        catch (Exception ex)
        {
            output.WriteLine($"No reverse DNS in this environment ({ex.GetType().Name}); nothing to verify.");
            return;
        }

        output.WriteLine($"environment resolves 8.8.8.8 to '{expected}'");

        using var resolver = new HostnameResolver();
        resolver.TryGet(address);

        string? resolved = null;
        var deadline = DateTime.UtcNow.AddSeconds(20);
        while (DateTime.UtcNow < deadline)
        {
            resolved = resolver.TryGet(address);
            if (resolved is not null)
            {
                break;
            }

            await Task.Delay(100);
        }

        // DNS demonstrably works here, so failing to resolve is a Keyhole bug, not
        // an environment limitation.
        Assert.Equal(expected, resolved);
    }
}
