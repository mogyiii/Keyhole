using System.Text;

namespace Keyhole.Core.Capture.Decode;

/// <summary>
/// Decodes HTTP/2 header blocks (HPACK, RFC 7541).
///
/// HPACK is stateful by design: a header can be sent as a one-byte reference to something
/// sent earlier on the same connection. That is what makes HTTP/2 headers small, and it is
/// also why a decoder must see every header block of a connection, in order. Skip one and
/// the dynamic table diverges, after which later blocks decode into the wrong headers —
/// not into an error.
///
/// One decoder instance therefore belongs to one direction of one connection, and lives as
/// long as it does.
/// </summary>
public sealed class HpackDecoder
{
    /// <summary>
    /// Headers sent earlier on this connection, most recent first.
    ///
    /// Indices continue on from the static table, so entry 62 is the newest. Insertions at
    /// the front make the older entries' indices shift, which is exactly the semantics the
    /// RFC specifies.
    /// </summary>
    private readonly List<HttpHeader> _dynamicTable = [];

    private int _dynamicTableBytes;

    /// <summary>
    /// The agreed ceiling on the dynamic table, which the peer can lower mid-connection.
    ///
    /// 4096 is the protocol default. A real peer announces its own limit in SETTINGS, which
    /// this decoder does not read — so the default is used, and a peer that raised its
    /// limit could in principle overflow it here. The consequence is an entry evicted
    /// earlier than the encoder expects, which is why an eviction mismatch is reported
    /// rather than ignored.
    /// </summary>
    private int _maxDynamicTableBytes = 4096;

    /// <summary>
    /// Per-entry overhead the RFC defines for table accounting: 32 bytes on top of the
    /// name and value lengths. Not a real memory figure — it is a fixed convention so that
    /// both ends agree on when eviction happens.
    /// </summary>
    private const int EntryOverhead = 32;

    /// <summary>
    /// Set once something could not be decoded. The dynamic table is then out of step with
    /// the encoder's, so every later block on this connection is suspect too.
    /// </summary>
    public string? Error { get; private set; }

    public bool IsBroken => Error is not null;

    /// <summary>
    /// Decodes one header block.
    /// </summary>
    /// <returns>
    /// The headers in the order they were sent, or null when the block could not be
    /// decoded — in which case this decoder is finished for the rest of the connection.
    /// </returns>
    public IReadOnlyList<HttpHeader>? Decode(ReadOnlySpan<byte> block)
    {
        if (IsBroken)
        {
            return null;
        }

        var headers = new List<HttpHeader>();
        var offset = 0;

        while (offset < block.Length)
        {
            var first = block[offset];

            // Indexed Header Field: the whole header is a reference. 1xxxxxxx.
            if ((first & 0x80) != 0)
            {
                if (!TryReadInteger(block, ref offset, 7, out var index))
                {
                    return Fail("a truncated indexed header field");
                }

                if (Lookup((int)index) is not { } indexed)
                {
                    return Fail($"a reference to header index {index}, which does not exist");
                }

                headers.Add(indexed);
                continue;
            }

            // Literal Header Field with Incremental Indexing: 01xxxxxx. Adds to the table.
            if ((first & 0x40) != 0)
            {
                if (!TryReadLiteral(block, ref offset, 6, out var header))
                {
                    return Fail("a truncated indexed literal header field");
                }

                headers.Add(header!);
                Insert(header!);
                continue;
            }

            // Dynamic Table Size Update: 001xxxxx. Not a header at all.
            if ((first & 0x20) != 0)
            {
                if (!TryReadInteger(block, ref offset, 5, out var size))
                {
                    return Fail("a truncated dynamic table size update");
                }

                Resize((int)size);
                continue;
            }

            // Literal without Indexing (0000xxxx) or Never Indexed (0001xxxx). Both are
            // read the same way; the difference only matters to an encoder deciding what a
            // proxy may remember.
            if (!TryReadLiteral(block, ref offset, 4, out var literal))
            {
                return Fail("a truncated literal header field");
            }

            headers.Add(literal!);
        }

        return headers;
    }

    private List<HttpHeader>? Fail(string what)
    {
        // Recorded rather than thrown: a connection whose headers stopped making sense is
        // a thing to report in the UI, not an exception to unwind a whole decode pass.
        Error = $"HPACK decoding stopped at {what}.";
        return null;
    }

    /// <summary>
    /// HPACK's variable-length integer encoding.
    ///
    /// The first byte carries the low bits inside the same byte as the field's type
    /// prefix; if those bits are all ones the value continues over following bytes, seven
    /// bits at a time. So the prefix width is part of the encoding and must match the
    /// field type exactly.
    /// </summary>
    private static bool TryReadInteger(
        ReadOnlySpan<byte> block, ref int offset, int prefixBits, out uint value)
    {
        value = 0;

        if (offset >= block.Length)
        {
            return false;
        }

        var mask = (1 << prefixBits) - 1;
        value = (uint)(block[offset] & mask);
        offset++;

        if (value < mask)
        {
            return true;
        }

        var shift = 0;

        while (true)
        {
            if (offset >= block.Length)
            {
                return false;
            }

            var b = block[offset];
            offset++;

            // A length field is bounded in practice; refusing a value that cannot describe
            // anything real stops a malformed block from being read as a huge allocation.
            if (shift > 21)
            {
                return false;
            }

            value += (uint)(b & 0x7f) << shift;
            shift += 7;

            if ((b & 0x80) == 0)
            {
                return true;
            }
        }
    }

    /// <summary>
    /// Reads a literal header field: a name that is either a table reference or a string,
    /// then a string value.
    /// </summary>
    private bool TryReadLiteral(
        ReadOnlySpan<byte> block, ref int offset, int prefixBits, out HttpHeader? header)
    {
        header = null;

        if (!TryReadInteger(block, ref offset, prefixBits, out var nameIndex))
        {
            return false;
        }

        string name;

        if (nameIndex == 0)
        {
            // A new name, sent as a string.
            if (!TryReadString(block, ref offset, out var read))
            {
                return false;
            }

            name = read!;
        }
        else
        {
            if (Lookup((int)nameIndex) is not { } existing)
            {
                return false;
            }

            name = existing.Name;
        }

        if (!TryReadString(block, ref offset, out var value))
        {
            return false;
        }

        header = new HttpHeader(name, value!);
        return true;
    }

    /// <summary>
    /// Reads a length-prefixed string, Huffman-coded or not.
    ///
    /// The top bit of the length byte says which. Getting that wrong yields a header full
    /// of binary rather than an error, so it is read rather than guessed.
    /// </summary>
    private static bool TryReadString(ReadOnlySpan<byte> block, ref int offset, out string? value)
    {
        value = null;

        if (offset >= block.Length)
        {
            return false;
        }

        var huffman = (block[offset] & 0x80) != 0;

        if (!TryReadInteger(block, ref offset, 7, out var length))
        {
            return false;
        }

        if (offset + length > block.Length)
        {
            return false;
        }

        var raw = block.Slice(offset, (int)length);
        offset += (int)length;

        if (!huffman)
        {
            value = Encoding.Latin1.GetString(raw);
            return true;
        }

        var decoded = HpackHuffman.Decode(raw);
        if (decoded is null)
        {
            return false;
        }

        // Latin1 rather than UTF-8: header values are bytes, and decoding them as UTF-8
        // would replace anything non-conforming with substitution characters, losing what
        // was actually sent.
        value = Encoding.Latin1.GetString(decoded);
        return true;
    }

    /// <summary>
    /// Resolves an index against the static table, then the dynamic one.
    ///
    /// The two share a single index space: 1-61 are static, 62 upwards are dynamic with
    /// the newest first. Indices are one-based, and treating them as zero-based returns a
    /// neighbouring header — wrong, and entirely plausible-looking.
    /// </summary>
    private HttpHeader? Lookup(int index)
    {
        if (index <= 0)
        {
            return null;
        }

        if (index <= HpackStaticTable.Entries.Length)
        {
            return HpackStaticTable.Entries[index - 1];
        }

        var dynamicIndex = index - HpackStaticTable.Entries.Length - 1;

        return dynamicIndex < _dynamicTable.Count ? _dynamicTable[dynamicIndex] : null;
    }

    private void Insert(HttpHeader header)
    {
        var size = header.Name.Length + header.Value.Length + EntryOverhead;

        // An entry larger than the whole table empties it and is not stored. Specified
        // behaviour, not an error.
        if (size > _maxDynamicTableBytes)
        {
            _dynamicTable.Clear();
            _dynamicTableBytes = 0;
            return;
        }

        _dynamicTable.Insert(0, header);
        _dynamicTableBytes += size;

        Evict();
    }

    private void Resize(int maxBytes)
    {
        _maxDynamicTableBytes = maxBytes;
        Evict();
    }

    private void Evict()
    {
        while (_dynamicTableBytes > _maxDynamicTableBytes && _dynamicTable.Count > 0)
        {
            var last = _dynamicTable[^1];
            _dynamicTableBytes -= last.Name.Length + last.Value.Length + EntryOverhead;
            _dynamicTable.RemoveAt(_dynamicTable.Count - 1);
        }
    }
}

/// <summary>
/// HPACK's static table (RFC 7541, Appendix A): the 61 headers common enough that both
/// ends can refer to them by number without either having sent them.
/// </summary>
internal static class HpackStaticTable
{
    internal static readonly HttpHeader[] Entries =
    [
        new(":authority", ""),
        new(":method", "GET"),
        new(":method", "POST"),
        new(":path", "/"),
        new(":path", "/index.html"),
        new(":scheme", "http"),
        new(":scheme", "https"),
        new(":status", "200"),
        new(":status", "204"),
        new(":status", "206"),
        new(":status", "304"),
        new(":status", "400"),
        new(":status", "404"),
        new(":status", "500"),
        new("accept-charset", ""),
        new("accept-encoding", "gzip, deflate"),
        new("accept-language", ""),
        new("accept-ranges", ""),
        new("accept", ""),
        new("access-control-allow-origin", ""),
        new("age", ""),
        new("allow", ""),
        new("authorization", ""),
        new("cache-control", ""),
        new("content-disposition", ""),
        new("content-encoding", ""),
        new("content-language", ""),
        new("content-length", ""),
        new("content-location", ""),
        new("content-range", ""),
        new("content-type", ""),
        new("cookie", ""),
        new("date", ""),
        new("etag", ""),
        new("expect", ""),
        new("expires", ""),
        new("from", ""),
        new("host", ""),
        new("if-match", ""),
        new("if-modified-since", ""),
        new("if-none-match", ""),
        new("if-range", ""),
        new("if-unmodified-since", ""),
        new("last-modified", ""),
        new("link", ""),
        new("location", ""),
        new("max-forwards", ""),
        new("proxy-authenticate", ""),
        new("proxy-authorization", ""),
        new("range", ""),
        new("referer", ""),
        new("refresh", ""),
        new("retry-after", ""),
        new("server", ""),
        new("set-cookie", ""),
        new("strict-transport-security", ""),
        new("transfer-encoding", ""),
        new("user-agent", ""),
        new("vary", ""),
        new("via", ""),
        new("www-authenticate", ""),
    ];
}
