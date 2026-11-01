using System.Net;
using MaxMind.Db;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Keyhole.Core.Monitoring;

/// <summary>
/// Resolves a remote address to a country and a network operator, from MaxMind MMDB files
/// on disk.
///
/// Entirely offline, and that is the point rather than a convenience: a tool that exists
/// to show what other programs send must not quietly start sending lookups of its own.
/// Every address a user is curious about would otherwise become a request to a third
/// party, which is precisely the behaviour Keyhole is for catching.
///
/// The databases are not shipped. MaxMind requires an account to download them and its
/// licence governs redistribution, so Keyhole reads whatever the user puts in the geoip
/// folder and says so plainly when there is nothing there — the same arrangement as Npcap.
/// </summary>
public sealed class GeoIpLookup : IGeoIpLookup, IDisposable
{
    private readonly ILogger _logger;
    private readonly Reader? _country;
    private readonly Reader? _asn;

    /// <summary>
    /// Results by address. Lookups are fast, but the monitor asks about the same addresses
    /// on every sample, and a cache turns a per-sample cost into a per-address one.
    /// </summary>
    private readonly Dictionary<string, GeoIpInfo> _cache = new(StringComparer.OrdinalIgnoreCase);

    private readonly Lock _gate = new();

    /// <summary>
    /// A crude bound. Entries are small and a machine does not talk to unboundedly many
    /// addresses, but a long-running service should not grow without a limit either.
    /// </summary>
    private const int MaxCacheEntries = 20_000;

    /// <summary>
    /// File names Keyhole looks for, in preference order.
    ///
    /// The City database carries country data too, so it is accepted in place of the
    /// Country one — a user who already has City should not need to fetch both.
    /// </summary>
    private static readonly string[] CountryFiles =
        ["GeoLite2-Country.mmdb", "GeoIP2-Country.mmdb", "GeoLite2-City.mmdb", "GeoIP2-City.mmdb"];

    private static readonly string[] AsnFiles =
        ["GeoLite2-ASN.mmdb", "GeoIP2-ISP.mmdb"];

    public GeoIpLookup(string? directory = null, ILogger<GeoIpLookup>? logger = null)
    {
        _logger = logger ?? NullLogger<GeoIpLookup>.Instance;

        var root = directory ?? KeyholePaths.GeoIpDirectory;

        _country = Open(root, CountryFiles, "country");
        _asn = Open(root, AsnFiles, "ASN");

        Directory = root;
    }

    /// <summary>Where the databases were looked for, so the UI can name the folder.</summary>
    public string Directory { get; }

    public bool IsAvailable => _country is not null || _asn is not null;

    /// <summary>
    /// What is missing, or null when both databases are loaded.
    ///
    /// Deliberately names the folder and the files: "GeoIP unavailable" leaves the user
    /// with nothing to do about it.
    /// </summary>
    public string? UnavailableReason =>
        (_country, _asn) switch
        {
            (null, null) =>
                $"No GeoIP database found. Put {CountryFiles[0]} and {AsnFiles[0]} in " +
                $"{Directory} to see countries and network operators. Keyhole does not " +
                "download them: they are MaxMind's, and need a free account.",

            (null, _) => $"No country database in {Directory}; add {CountryFiles[0]} to see countries.",
            (_, null) => $"No ASN database in {Directory}; add {AsnFiles[0]} to see network operators.",
            _ => null,
        };

    public GeoIpInfo Lookup(IPAddress address)
    {
        if (!IsAvailable || IsUninteresting(address))
        {
            return GeoIpInfo.Unknown;
        }

        var key = address.ToString();

        lock (_gate)
        {
            if (_cache.TryGetValue(key, out var cached))
            {
                return cached;
            }
        }

        var info = Resolve(address);

        lock (_gate)
        {
            if (_cache.Count >= MaxCacheEntries)
            {
                // Results are cheap to recompute and the cache is only an optimisation,
                // so dropping everything beats tracking per-entry recency.
                _cache.Clear();
            }

            _cache[key] = info;
        }

        return info;
    }

    /// <summary>
    /// Addresses no database has anything to say about: loopback, link-local and the
    /// private ranges. Asking about them wastes a lookup and, worse, a miss would read as
    /// "unknown country" when the truth is "this never left the network".
    /// </summary>
    private static bool IsUninteresting(IPAddress address)
    {
        if (IPAddress.IsLoopback(address) ||
            address.Equals(IPAddress.Any) ||
            address.Equals(IPAddress.IPv6Any))
        {
            return true;
        }

        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            return address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6Multicast;
        }

        var bytes = address.GetAddressBytes();

        return bytes[0] switch
        {
            10 => true,                                 // 10.0.0.0/8
            127 => true,                                // loopback, already handled
            169 when bytes[1] == 254 => true,           // link-local
            172 when bytes[1] is >= 16 and <= 31 => true, // 172.16.0.0/12
            192 when bytes[1] == 168 => true,           // 192.168.0.0/16
            >= 224 => true,                             // multicast and reserved
            _ => false,
        };
    }

    private GeoIpInfo Resolve(IPAddress address)
    {
        string? countryCode = null;
        string? countryName = null;
        long? asn = null;
        string? organisation = null;

        try
        {
            if (_country?.Find<Dictionary<string, object>>(address) is { } countryRecord &&
                countryRecord.TryGetValue("country", out var country) &&
                country is Dictionary<string, object> countryFields)
            {
                countryCode = countryFields.TryGetValue("iso_code", out var iso)
                    ? iso as string
                    : null;

                // Names are a map of locale to string; English is the one Keyhole shows.
                if (countryFields.TryGetValue("names", out var names) &&
                    names is Dictionary<string, object> localised &&
                    localised.TryGetValue("en", out var english))
                {
                    countryName = english as string;
                }
            }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // A corrupt or unexpected database must not take monitoring down over one
            // address; the column simply stays empty.
            _logger.LogDebug(ex, "Country lookup failed for {Address}.", address);
        }

        try
        {
            if (_asn?.Find<Dictionary<string, object>>(address) is { } asnRecord)
            {
                if (asnRecord.TryGetValue("autonomous_system_number", out var number))
                {
                    asn = number switch
                    {
                        long l => l,
                        int i => i,
                        ulong u => (long)u,
                        uint u => u,
                        _ => null,
                    };
                }

                if (asnRecord.TryGetValue("autonomous_system_organization", out var org))
                {
                    organisation = org as string;
                }

                // The ISP database names the field differently.
                if (organisation is null && asnRecord.TryGetValue("isp", out var isp))
                {
                    organisation = isp as string;
                }
            }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            _logger.LogDebug(ex, "ASN lookup failed for {Address}.", address);
        }

        return new GeoIpInfo(countryCode, countryName, asn, organisation);
    }

    private Reader? Open(string root, string[] candidates, string what)
    {
        foreach (var name in candidates)
        {
            var path = Path.Combine(root, name);

            try
            {
                if (!File.Exists(path))
                {
                    continue;
                }

                // Memory-mapped, so a 70 MB City database costs address space rather than
                // heap and is shared if anything else has it open.
                var reader = new Reader(path, FileAccessMode.MemoryMapped);

                _logger.LogInformation("Loaded {What} database from {Path}.", what, path);
                return reader;
            }
            catch (Exception ex)
            {
                // A truncated download or a file still being written. Try the next
                // candidate rather than failing the whole lookup.
                _logger.LogWarning(ex, "Could not open the {What} database at {Path}.", what, path);
            }
        }

        return null;
    }

    public void Dispose()
    {
        _country?.Dispose();
        _asn?.Dispose();
    }
}

/// <summary>
/// Where an address is and who operates it. Abstracted so the monitor can be tested
/// without a database on disk.
/// </summary>
public interface IGeoIpLookup
{
    bool IsAvailable { get; }

    /// <summary>What is missing, or null when lookups work.</summary>
    string? UnavailableReason { get; }

    GeoIpInfo Lookup(IPAddress address);
}

/// <summary>
/// What is known about one address. Every field is optional: the two databases are
/// separate, a user may have one and not the other, and a private address has neither.
/// </summary>
/// <param name="CountryCode">Two-letter ISO code, for a compact column.</param>
/// <param name="CountryName">The readable name, for a tooltip.</param>
/// <param name="AutonomousSystemNumber">The network's AS number.</param>
/// <param name="Organisation">Who operates that network — usually the more useful of the two.</param>
public readonly record struct GeoIpInfo(
    string? CountryCode,
    string? CountryName,
    long? AutonomousSystemNumber,
    string? Organisation)
{
    public static GeoIpInfo Unknown => default;

    public bool HasAnything =>
        CountryCode is not null || Organisation is not null || AutonomousSystemNumber is not null;
}

/// <summary>A lookup that knows nothing, for when no database is configured.</summary>
public sealed class NullGeoIpLookup(string reason) : IGeoIpLookup
{
    public bool IsAvailable => false;

    public string? UnavailableReason { get; } = reason;

    public GeoIpInfo Lookup(IPAddress address) => GeoIpInfo.Unknown;
}
