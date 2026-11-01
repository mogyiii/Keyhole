namespace Keyhole.Core.Capture.Decode;

/// <summary>
/// The Huffman code HPACK uses to compress header strings (RFC 7541, Appendix B).
///
/// Only the code <em>lengths</em> are stored, not the codes. HPACK's code is canonical:
/// within one length, codes are assigned in ascending symbol order, and each length's
/// first code follows from the previous length's last. So the codes are derivable, and
/// deriving them removes 257 hand-copied hex constants — every one of which would be a
/// chance for a transcription error that silently corrupts headers rather than failing.
///
/// A Huffman table is also self-checking. A complete prefix code satisfies the Kraft
/// equality, so the lengths sum to exactly one when treated as probabilities; any single
/// wrong length breaks it. That check runs once at startup and is what caught the one
/// error in this table during development.
/// </summary>
internal static class HpackHuffman
{
    /// <summary>
    /// Code length in bits for each of the 257 symbols: the 256 byte values, then the
    /// end-of-string symbol.
    /// </summary>
    private static readonly byte[] CodeLengths =
    [
        13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,   //   0- 15
        28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,   //  16- 31
         6, 10, 10, 12, 13,  6,  8, 11, 10, 10,  8, 11,  8,  6,  6,  6,   //  32- 47
         5,  5,  5,  6,  6,  6,  6,  6,  6,  6,  7,  8, 15,  6, 12, 10,   //  48- 63
        13,  6,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,   //  64- 79
         7,  7,  7,  7,  7,  7,  7,  7,  8,  7,  8, 13, 19, 13, 14,  6,   //  80- 95
        15,  5,  6,  5,  6,  5,  6,  6,  6,  5,  7,  7,  6,  6,  6,  5,   //  96-111
         6,  7,  6,  5,  5,  6,  7,  7,  7,  7,  7, 15, 11, 14, 13, 28,   // 112-127
        20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,   // 128-143
        24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,   // 144-159
        22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,   // 160-175
        21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,   // 176-191
        26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,   // 192-207
        19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,   // 208-223
        20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,   // 224-239
        26, 27, 26, 26, 27, 27, 26, 27, 27, 27, 27, 27, 27, 27, 27, 28,   // 240-255
        30,                                                                // 256 (EOS)
    ];

    /// <summary>
    /// The decoding table: code value to symbol, grouped by code length.
    ///
    /// Built once from the lengths above. For each length, the first code and the symbols
    /// in order are enough to decode by reading bits until the accumulated value falls
    /// within that length's range — which is the standard canonical-Huffman decode and
    /// needs no tree.
    /// </summary>
    private static readonly LengthGroup[] Groups = BuildGroups();

    /// <summary>The symbol meaning "string ends here"; it must never appear decoded.</summary>
    private const int EndOfString = 256;

    /// <summary>Longest code in the table, which bounds how far a decode may read.</summary>
    private const int MaxCodeLength = 30;

    private readonly record struct LengthGroup(uint FirstCode, int FirstSymbolIndex, int Count);

    /// <summary>Symbols ordered by (code length, symbol value) — canonical code order.</summary>
    private static readonly int[] SymbolsInCodeOrder = BuildSymbolOrder();

    private static int[] BuildSymbolOrder()
    {
        var order = new List<int>(CodeLengths.Length);

        for (var length = 1; length <= MaxCodeLength; length++)
        {
            for (var symbol = 0; symbol < CodeLengths.Length; symbol++)
            {
                if (CodeLengths[symbol] == length)
                {
                    order.Add(symbol);
                }
            }
        }

        return [.. order];
    }

    private static LengthGroup[] BuildGroups()
    {
        var groups = new LengthGroup[MaxCodeLength + 1];
        var counts = new int[MaxCodeLength + 1];

        foreach (var length in CodeLengths)
        {
            counts[length]++;
        }

        var code = 0u;
        var index = 0;

        for (var length = 1; length <= MaxCodeLength; length++)
        {
            groups[length] = new LengthGroup(code, index, counts[length]);
            index += counts[length];

            // Each length's codes are consecutive, and the next length starts just past
            // the end of this one, shifted left by one bit.
            code = (code + (uint)counts[length]) << 1;
        }

        return groups;
    }

    /// <summary>
    /// Whether the table is a complete prefix code.
    ///
    /// Checked rather than assumed. A single mistyped length produces a table that decodes
    /// most input plausibly and some input into silent nonsense, which is the worst
    /// possible failure mode for something that renders a user's HTTP headers.
    /// </summary>
    internal static bool IsComplete()
    {
        // Kraft's equality, evaluated in integers against 2^30 to avoid any question of
        // floating-point tolerance.
        var total = 0L;

        foreach (var length in CodeLengths)
        {
            total += 1L << (MaxCodeLength - length);
        }

        return total == 1L << MaxCodeLength;
    }

    /// <summary>
    /// Decodes a Huffman-coded header string.
    /// </summary>
    /// <returns>
    /// The decoded bytes, or null when the input is not a valid coding — an over-long
    /// pad, a code that is not in the table, or an end-of-string symbol in the middle.
    /// Returning null rather than partial output matters: a header decoded halfway is
    /// worse than one reported as undecodable.
    /// </returns>
    public static byte[]? Decode(ReadOnlySpan<byte> encoded)
    {
        var output = new List<byte>(encoded.Length * 2);

        // 64-bit, not 32: the longest code is 30 bits, so up to 29 can be left over
        // waiting for more input, and the next byte pushes that to 37. A 32-bit
        // accumulator silently drops the top bits of exactly those long codes — which are
        // the rare high byte values, so the damage would only appear on unusual headers.
        var accumulator = 0UL;
        var bits = 0;

        foreach (var b in encoded)
        {
            accumulator = (accumulator << 8) | b;
            bits += 8;

            // Pull out as many whole symbols as the accumulated bits allow.
            while (true)
            {
                var symbol = TryTake(ref accumulator, ref bits);

                if (symbol is null)
                {
                    break;
                }

                if (symbol == EndOfString)
                {
                    // EOS is only ever used as padding, and padding is never a whole
                    // symbol — so decoding one means the input is malformed.
                    return null;
                }

                output.Add((byte)symbol.Value);
            }
        }

        // What remains must be padding: up to seven bits, all ones, which is the prefix of
        // the EOS code. Anything else means a truncated or corrupt string.
        if (bits >= 8)
        {
            return null;
        }

        if (bits > 0)
        {
            var padding = accumulator & ((1UL << bits) - 1);
            if (padding != (1UL << bits) - 1)
            {
                return null;
            }
        }

        return [.. output];
    }

    /// <summary>
    /// Takes the next whole symbol from the bit accumulator, or returns null when more
    /// bits are needed.
    /// </summary>
    private static int? TryTake(ref ulong accumulator, ref int bits)
    {
        for (var length = 1; length <= MaxCodeLength && length <= bits; length++)
        {
            var group = Groups[length];
            if (group.Count == 0)
            {
                continue;
            }

            // The candidate is the top `length` bits of what has accumulated.
            var candidate = accumulator >> (bits - length);

            if (candidate >= group.FirstCode && candidate < group.FirstCode + (ulong)group.Count)
            {
                var symbol = SymbolsInCodeOrder[group.FirstSymbolIndex + (int)(candidate - group.FirstCode)];

                bits -= length;
                accumulator &= bits == 0 ? 0 : (1UL << bits) - 1;

                return symbol;
            }
        }

        return null;
    }
}
