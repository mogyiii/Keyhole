using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Keyhole.Core.Monitoring;

/// <summary>
/// Reverse-DNS cache that answers immediately and resolves in the background.
///
/// A reverse lookup can take seconds or hang entirely. The sampling loop runs on a short
/// interval, so resolution is strictly fire-and-forget: callers get whatever is cached
/// now, and later samples pick up names as they arrive.
/// </summary>
public sealed class HostnameResolver : IHostnameResolver, IDisposable
{
    private readonly ILogger _logger;
    private readonly ConcurrentDictionary<string, CacheEntry> _cache = new();
    private readonly ConcurrentDictionary<string, byte> _inFlight = new();
    private readonly SemaphoreSlim _concurrency;
    private readonly CancellationTokenSource _shutdown = new();

    /// <summary>Successful names are stable enough to keep for a long while.</summary>
    private static readonly TimeSpan PositiveTtl = TimeSpan.FromHours(6);

    /// <summary>
    /// "This address has no PTR record" is a durable fact. Without caching it, every
    /// sample would re-query the same unresolvable address forever.
    /// </summary>
    private static readonly TimeSpan NoRecordTtl = TimeSpan.FromMinutes(10);

    /// <summary>
    /// A timeout or a busy resolver says nothing about the address, only about this moment.
    /// Caching that for as long as a real negative answer would blank out hostnames for
    /// ten minutes after one DNS hiccup.
    /// </summary>
    private static readonly TimeSpan TransientFailureTtl = TimeSpan.FromSeconds(20);

    private const int MaxCacheEntries = 8192;
    private const int MaxConcurrentLookups = 8;

    private readonly Func<IPAddress, CancellationToken, Task<string?>> _lookup;

    public HostnameResolver(ILogger<HostnameResolver>? logger = null)
        : this(null, logger)
    {
    }

    /// <summary>
    /// <paramref name="lookup"/> overrides how a name is fetched. Tests inject a
    /// deterministic one so cache and concurrency behaviour can be asserted without
    /// depending on a live resolver.
    /// </summary>
    public HostnameResolver(
        Func<IPAddress, CancellationToken, Task<string?>>? lookup,
        ILogger<HostnameResolver>? logger = null)
    {
        _logger = logger ?? NullLogger<HostnameResolver>.Instance;
        _lookup = lookup ?? DefaultLookupAsync;
        _concurrency = new SemaphoreSlim(MaxConcurrentLookups, MaxConcurrentLookups);
    }

    private static async Task<string?> DefaultLookupAsync(IPAddress address, CancellationToken ct)
    {
        var entry = await Dns.GetHostEntryAsync(address).WaitAsync(TimeSpan.FromSeconds(3), ct)
            .ConfigureAwait(false);

        return string.IsNullOrWhiteSpace(entry.HostName) ? null : entry.HostName;
    }

    public string? TryGet(IPAddress address)
    {
        if (!ShouldResolve(address))
        {
            return null;
        }

        var key = address.ToString();

        if (_cache.TryGetValue(key, out var entry))
        {
            if (DateTime.UtcNow < entry.ExpiresUtc)
            {
                return entry.Hostname;
            }

            _cache.TryRemove(key, out _);
        }

        QueueLookup(address, key);
        return null;
    }

    /// <summary>
    /// Addresses that never have useful reverse records. Querying them wastes the lookup
    /// budget and, for private ranges, can leak internal addresses to an external resolver.
    /// </summary>
    private static bool ShouldResolve(IPAddress address)
    {
        if (IPAddress.IsLoopback(address) ||
            address.Equals(IPAddress.Any) ||
            address.Equals(IPAddress.IPv6Any))
        {
            return false;
        }

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var octets = address.GetAddressBytes();

            // 0.0.0.0/8, 169.254/16 link-local, 224/4 multicast and up.
            if (octets[0] is 0 or >= 224)
            {
                return false;
            }

            if (octets[0] == 169 && octets[1] == 254)
            {
                return false;
            }
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6 &&
            (address.IsIPv6LinkLocal || address.IsIPv6Multicast))
        {
            return false;
        }

        return true;
    }

    private void QueueLookup(IPAddress address, string key)
    {
        // One lookup per address at a time; a busy connection produces the same address
        // on every sample and would otherwise queue dozens of identical queries.
        if (!_inFlight.TryAdd(key, 0))
        {
            return;
        }

        _ = Task.Run(async () =>
        {
            try
            {
                await _concurrency.WaitAsync(_shutdown.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                _inFlight.TryRemove(key, out _);
                return;
            }

            try
            {
                var entry = await LookupAsync(address).ConfigureAwait(false);
                Store(key, entry);
            }
            finally
            {
                _concurrency.Release();
                _inFlight.TryRemove(key, out _);
            }
        }, CancellationToken.None);
    }

    private async Task<CacheEntry> LookupAsync(IPAddress address)
    {
        try
        {
            var name = await _lookup(address, _shutdown.Token).ConfigureAwait(false);

            return name is null
                ? new CacheEntry(null, DateTime.UtcNow + NoRecordTtl)
                : new CacheEntry(name, DateTime.UtcNow + PositiveTtl);
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.HostNotFound)
        {
            // A definitive "no PTR record" — the common case, not worth logging per address.
            return new CacheEntry(null, DateTime.UtcNow + NoRecordTtl);
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException
                                      or TimeoutException or ArgumentException)
        {
            // Resolver busy, timed out, or shutting down. This says nothing about the
            // address itself, so retry soon instead of blanking the name for the full
            // negative TTL after one hiccup.
            return new CacheEntry(null, DateTime.UtcNow + TransientFailureTtl);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Reverse lookup for {Address} failed unexpectedly.", address);
            return new CacheEntry(null, DateTime.UtcNow + TransientFailureTtl);
        }
    }

    private void Store(string key, CacheEntry entry)
    {
        if (_cache.Count >= MaxCacheEntries)
        {
            // Drop the expired first; if that frees nothing, the cache is genuinely hot
            // and clearing it is better than growing without bound.
            foreach (var (existingKey, existing) in _cache)
            {
                if (DateTime.UtcNow >= existing.ExpiresUtc)
                {
                    _cache.TryRemove(existingKey, out _);
                }
            }

            if (_cache.Count >= MaxCacheEntries)
            {
                _cache.Clear();
            }
        }

        _cache[key] = entry;
    }

    public void Dispose()
    {
        _shutdown.Cancel();
        _shutdown.Dispose();
        _concurrency.Dispose();
    }

    private readonly record struct CacheEntry(string? Hostname, DateTime ExpiresUtc);
}
