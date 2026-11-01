using System.Buffers.Binary;
using System.Text;

namespace Keyhole.Tests;

/// <summary>
/// Builds a minimal but real MaxMind MMDB file.
///
/// Needed because the database files are MaxMind's: they require an account, their licence
/// governs redistribution, and Keyhole therefore ships none. Without one, the part of the
/// GeoIP code that actually matters — pulling the right fields out of a record — would
/// never run in a test, and a wrong field name produces a blank column rather than an
/// error. That is the same failure mode as a mistyped Huffman length, and it gets the same
/// treatment: build a real file and read it back through the real reader.
///
/// Deliberately tiny. The search tree is a single node whose two records both point at the
/// one data record, so every address in the file's family resolves to it. That is useless
/// as a geolocation database and exactly right for checking field extraction.
/// </summary>
internal static class MmdbBuilder
{
    /// <summary>The marker that separates the data section from the metadata.</summary>
    private static readonly byte[] MetadataMarker =
        [0xAB, 0xCD, 0xEF, .. "MaxMind.com"u8];

    /// <summary>Bytes of zero between the search tree and the data section, per the spec.</summary>
    private const int SeparatorBytes = 16;

    private const int NodeCount = 1;
    private const int RecordSizeBits = 32;

    /// <summary>
    /// Writes a country database whose every IPv4 address resolves to the given country.
    /// </summary>
    public static void WriteCountryDatabase(string path, string isoCode, string englishName)
    {
        var record = Map(
            ("country", Map(
                ("iso_code", Utf8(isoCode)),
                ("names", Map(("en", Utf8(englishName)))))));

        Write(path, "GeoLite2-Country", record);
    }

    /// <summary>
    /// Writes an ASN database whose every IPv4 address resolves to the given network.
    /// </summary>
    public static void WriteAsnDatabase(string path, long asn, string organisation)
    {
        var record = Map(
            ("autonomous_system_number", UInt32((uint)asn)),
            ("autonomous_system_organization", Utf8(organisation)));

        Write(path, "GeoLite2-ASN", record);
    }

    private static void Write(string path, string databaseType, byte[] dataRecord)
    {
        using var file = new MemoryStream();

        // A pointer record's value is the data offset plus the node count plus the
        // separator size. The single record sits at offset zero in the data section.
        const uint pointer = NodeCount + SeparatorBytes;

        Span<byte> node = stackalloc byte[RecordSizeBits * 2 / 8];
        BinaryPrimitives.WriteUInt32BigEndian(node, pointer);
        BinaryPrimitives.WriteUInt32BigEndian(node[4..], pointer);
        file.Write(node);

        file.Write(new byte[SeparatorBytes]);
        file.Write(dataRecord);

        file.Write(MetadataMarker);
        file.Write(Metadata(databaseType));

        File.WriteAllBytes(path, file.ToArray());
    }

    private static byte[] Metadata(string databaseType) => Map(
        ("node_count", UInt32(NodeCount)),
        ("record_size", UInt16(RecordSizeBits)),

        // IPv4 only, which keeps the tree a single node: an IPv6 database would have to
        // carry the ::ffff:0:0/96 mapping as well.
        ("ip_version", UInt16(4)),

        ("database_type", Utf8(databaseType)),
        ("languages", Array(Utf8("en"))),
        ("binary_format_major_version", UInt16(2)),
        ("binary_format_minor_version", UInt16(0)),
        ("build_epoch", UInt64(1762000000)),
        ("description", Map(("en", Utf8("Keyhole test database")))));

    // --- the data-section encoding -------------------------------------------------
    //
    // Every value is a control byte carrying a 3-bit type and a 5-bit size, followed by
    // that many bytes. A size of 29 or more is encoded over extra bytes; nothing here
    // needs that, and the assertion below keeps it honest rather than silently wrong.

    private const int TypeUtf8String = 2;
    private const int TypeUInt16 = 5;
    private const int TypeUInt32 = 6;
    private const int TypeMap = 7;
    private const int TypeUInt64 = 9;
    private const int TypeArray = 11;

    private static byte[] Utf8(string value) => Tagged(TypeUtf8String, Encoding.UTF8.GetBytes(value));

    private static byte[] UInt16(ushort value) => Tagged(TypeUInt16, TrimLeadingZeros(value));

    private static byte[] UInt32(uint value) => Tagged(TypeUInt32, TrimLeadingZeros(value));

    private static byte[] UInt64(ulong value) => Tagged(TypeUInt64, TrimLeadingZeros(value));

    private static byte[] Map(params (string Key, byte[] Value)[] entries)
    {
        var body = new MemoryStream();

        foreach (var (key, value) in entries)
        {
            body.Write(Utf8(key));
            body.Write(value);
        }

        return WithControl(TypeMap, entries.Length, body.ToArray());
    }

    private static byte[] Array(params byte[][] items)
    {
        var body = new MemoryStream();

        foreach (var item in items)
        {
            body.Write(item);
        }

        return WithControl(TypeArray, items.Length, body.ToArray());
    }

    /// <summary>A value whose control-byte size is its payload length.</summary>
    private static byte[] Tagged(int type, byte[] payload) =>
        WithControl(type, payload.Length, payload);

    /// <summary>
    /// Prefixes a payload with its control byte.
    /// </summary>
    /// <param name="size">
    /// For strings and numbers this is the byte count; for maps and arrays it is the
    /// number of entries. The two meanings share one field in the format.
    /// </param>
    private static byte[] WithControl(int type, int size, byte[] payload)
    {
        var result = new MemoryStream();

        // The low five bits hold the size directly up to 28. Above that they hold a
        // marker and the real size follows the control byte — and that threshold is not
        // academic: "autonomous_system_organization" is 30 characters, so the very first
        // real database this builder wrote needed the extended form.
        var (sizeBits, sizeBytes) = size switch
        {
            < 29 => (size, System.Array.Empty<byte>()),
            < 285 => (29, new[] { (byte)(size - 29) }),
            _ => throw new ArgumentOutOfRangeException(
                nameof(size),
                "This builder encodes sizes below 285; no test database needs more."),
        };

        // Types 1-7 fit the control byte's top three bits. Anything above goes in as type
        // zero with the real type in the following byte, and the size extension comes
        // after that.
        if (type <= 7)
        {
            result.WriteByte((byte)((type << 5) | sizeBits));
        }
        else
        {
            result.WriteByte((byte)sizeBits);
            result.WriteByte((byte)(type - 7));
        }

        result.Write(sizeBytes);
        result.Write(payload);

        return result.ToArray();
    }

    /// <summary>
    /// Big-endian bytes with leading zeros removed, which is how the format stores
    /// integers: the control byte's size says how many bytes follow.
    /// </summary>
    private static byte[] TrimLeadingZeros(ulong value)
    {
        Span<byte> full = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(full, value);

        var start = 0;
        while (start < full.Length - 1 && full[start] == 0)
        {
            start++;
        }

        // Zero encodes as no bytes at all, which the size field expresses as 0.
        return value == 0 ? [] : full[start..].ToArray();
    }
}
