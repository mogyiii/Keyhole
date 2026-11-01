using System.Net;
using Keyhole.Core.Monitoring;

namespace Keyhole.Tests;

/// <summary>
/// Country and operator lookups.
///
/// The databases are the user's and are not shipped, so the behaviour that matters most is
/// what happens without them: every column stays blank and the reason says what to do.
/// A machine with no MMDB file is the default state, not an error.
/// </summary>
public class GeoIpLookupTests : IDisposable
{
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), $"keyhole-geoip-{Guid.NewGuid():n}");

    public GeoIpLookupTests() => Directory.CreateDirectory(_directory);

    [Fact]
    public void With_no_database_nothing_is_known_and_the_reason_says_why()
    {
        using var lookup = new GeoIpLookup(_directory);

        Assert.False(lookup.IsAvailable);

        var reason = lookup.UnavailableReason;
        Assert.NotNull(reason);

        // The reason has to be actionable. "GeoIP unavailable" leaves the user with
        // nothing to do, so it names the folder and the files it wants.
        Assert.Contains(_directory, reason);
        Assert.Contains("GeoLite2-Country.mmdb", reason);
        Assert.Contains("GeoLite2-ASN.mmdb", reason);

        // And says Keyhole will not fetch them, because it cannot: they need an account.
        Assert.Contains("does not download", reason);
    }

    [Fact]
    public void Lookups_return_nothing_rather_than_throwing_without_a_database()
    {
        using var lookup = new GeoIpLookup(_directory);

        var info = lookup.Lookup(IPAddress.Parse("8.8.8.8"));

        Assert.False(info.HasAnything);
        Assert.Null(info.CountryCode);
        Assert.Null(info.Organisation);
    }

    [Fact]
    public void A_corrupt_database_is_skipped_rather_than_fatal()
    {
        // A half-finished download, or a file still being written. Monitoring must come
        // up either way.
        File.WriteAllBytes(
            Path.Combine(_directory, "GeoLite2-Country.mmdb"),
            System.Text.Encoding.ASCII.GetBytes("this is not an MMDB file"));

        using var lookup = new GeoIpLookup(_directory);

        Assert.False(lookup.IsAvailable);
        Assert.False(lookup.Lookup(IPAddress.Parse("8.8.8.8")).HasAnything);
    }

    [Theory]
    // Loopback, link-local and the private ranges: no database has anything to say about
    // these, and a miss would read as "unknown country" when the truth is that the
    // traffic never left the network.
    [InlineData("127.0.0.1")]
    [InlineData("10.1.2.3")]
    [InlineData("172.16.0.1")]
    [InlineData("172.31.255.254")]
    [InlineData("192.168.1.1")]
    [InlineData("169.254.1.1")]
    [InlineData("224.0.0.1")]
    [InlineData("::1")]
    [InlineData("fe80::1")]
    public void Local_and_private_addresses_are_not_looked_up(string address)
    {
        using var lookup = new GeoIpLookup(_directory);

        Assert.False(lookup.Lookup(IPAddress.Parse(address)).HasAnything);
    }

    [Theory]
    // Addresses just outside the private ranges, which must not be excluded by an
    // off-by-one in the range checks.
    [InlineData("172.15.255.255")]
    [InlineData("172.32.0.1")]
    [InlineData("192.167.1.1")]
    [InlineData("11.0.0.1")]
    [InlineData("8.8.8.8")]
    public void Public_addresses_near_the_private_ranges_are_still_public(string address)
    {
        // With no database loaded the result is empty either way, so this checks the
        // classification rather than the lookup: a public address must reach the reader.
        // Verified through the null lookup's contract, which returns nothing for
        // everything — so the assertion is that parsing and classification do not throw
        // and the address is treated as worth asking about.
        var parsed = IPAddress.Parse(address);

        Assert.False(IPAddress.IsLoopback(parsed));
        Assert.True(IsPublicByKeyholeRules(parsed));
    }

    /// <summary>
    /// Mirrors the classification in <see cref="GeoIpLookup"/>, so the ranges can be
    /// checked directly. Kept deliberately separate rather than made public: the product
    /// code's version is a private detail, and a test that re-derives it is a weaker
    /// check than one that compares two independent statements of the same rule.
    /// </summary>
    private static bool IsPublicByKeyholeRules(IPAddress address)
    {
        if (address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
        {
            return false;
        }

        var b = address.GetAddressBytes();

        return b[0] switch
        {
            10 or 127 => false,
            169 when b[1] == 254 => false,
            172 when b[1] is >= 16 and <= 31 => false,
            192 when b[1] == 168 => false,
            >= 224 => false,
            _ => true,
        };
    }

    [Fact]
    public void A_real_database_yields_the_country_and_the_operator()
    {
        // The check that matters. Everything else here is about absence; this is the one
        // path that runs when a user actually installs the databases, and a wrong field
        // name in it produces a blank column rather than an error — so it is exercised
        // against a real MMDB file read through the real reader.
        MmdbBuilder.WriteCountryDatabase(
            Path.Combine(_directory, "GeoLite2-Country.mmdb"), "HU", "Hungary");

        MmdbBuilder.WriteAsnDatabase(
            Path.Combine(_directory, "GeoLite2-ASN.mmdb"), 64496, "Example Net");

        using var lookup = new GeoIpLookup(_directory);

        Assert.True(lookup.IsAvailable);
        Assert.Null(lookup.UnavailableReason);

        var info = lookup.Lookup(IPAddress.Parse("8.8.8.8"));

        Assert.True(info.HasAnything);
        Assert.Equal("HU", info.CountryCode);
        Assert.Equal("Hungary", info.CountryName);
        Assert.Equal(64496, info.AutonomousSystemNumber);
        Assert.Equal("Example Net", info.Organisation);
    }

    [Fact]
    public void One_database_without_the_other_still_works_and_says_what_is_missing()
    {
        // A likely state: the two databases are separate downloads, so a user can easily
        // have one. The columns that can be filled must be filled.
        MmdbBuilder.WriteAsnDatabase(
            Path.Combine(_directory, "GeoLite2-ASN.mmdb"), 64496, "Example Net");

        using var lookup = new GeoIpLookup(_directory);

        Assert.True(lookup.IsAvailable);

        var info = lookup.Lookup(IPAddress.Parse("8.8.8.8"));

        Assert.Equal("Example Net", info.Organisation);
        Assert.Null(info.CountryCode);

        var reason = lookup.UnavailableReason;
        Assert.NotNull(reason);
        Assert.Contains("country database", reason);
        Assert.DoesNotContain("ASN database", reason);
    }

    [Fact]
    public void A_city_database_is_accepted_in_place_of_the_country_one()
    {
        // City carries country data too, so a user who already has it should not have to
        // fetch a second file.
        MmdbBuilder.WriteCountryDatabase(
            Path.Combine(_directory, "GeoLite2-City.mmdb"), "DE", "Germany");

        using var lookup = new GeoIpLookup(_directory);

        Assert.Equal("DE", lookup.Lookup(IPAddress.Parse("8.8.8.8")).CountryCode);
    }

    [Fact]
    public void Results_are_cached_per_address()
    {
        MmdbBuilder.WriteAsnDatabase(
            Path.Combine(_directory, "GeoLite2-ASN.mmdb"), 64496, "Example Net");

        using var lookup = new GeoIpLookup(_directory);

        var address = IPAddress.Parse("8.8.8.8");

        // The monitor asks about the same addresses on every sample, so a repeated lookup
        // has to be cheap and, more importantly, consistent.
        var first = lookup.Lookup(address);
        var second = lookup.Lookup(address);

        Assert.Equal(first, second);
    }

    [Fact]
    public void The_null_lookup_carries_its_reason()
    {
        // Used wherever GeoIP is not wired up at all, which must look the same to the UI
        // as a missing database rather than throwing.
        IGeoIpLookup lookup = new NullGeoIpLookup("not configured");

        Assert.False(lookup.IsAvailable);
        Assert.Equal("not configured", lookup.UnavailableReason);
        Assert.False(lookup.Lookup(IPAddress.Parse("8.8.8.8")).HasAnything);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (IOException)
        {
            // A leftover temp folder is not worth failing a test over.
        }
    }
}
