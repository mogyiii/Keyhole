using System.Text;
using Keyhole.Core.Capture.Decode;

namespace Keyhole.Tests;

/// <summary>
/// The Huffman table checked two ways, because a wrong entry does not throw — it decodes
/// headers into plausible nonsense.
///
/// First structurally: a complete prefix code satisfies Kraft's equality exactly, so a
/// single wrong length is arithmetically detectable without knowing which one it is. Then
/// against RFC 7541's own worked examples, which pin the actual code values rather than
/// only their shape.
/// </summary>
public class HpackHuffmanTests
{
    [Fact]
    public void The_table_is_a_complete_prefix_code()
    {
        // This is the check that found the real error in the table: one symbol had been
        // given a 28-bit code where the RFC gives it 27, and the sum came out short by
        // exactly that one code's weight.
        Assert.True(
            HpackHuffman.IsComplete(),
            "The Huffman code lengths do not form a complete prefix code, so some header " +
            "strings would decode to the wrong bytes.");
    }

    [Theory]
    // RFC 7541 Appendix C.4.1: the Huffman-coded header values of a GET request.
    [InlineData("f1e3c2e5f23a6ba0ab90f4ff", "www.example.com")]
    [InlineData("a8eb10649cbf", "no-cache")]
    // Appendix C.4.3.
    [InlineData("25a849e95ba97d7f", "custom-key")]
    [InlineData("25a849e95bb8e8b4bf", "custom-value")]
    // Appendix C.6.1: a response's values, including a date and a long Set-Cookie.
    [InlineData("6402", "302")]
    [InlineData("aec3771a4b", "private")]
    [InlineData("d07abe941054d444a8200595040b8166e082a62d1bff", "Mon, 21 Oct 2013 20:13:21 GMT")]
    [InlineData("9d29ad171863c78f0b97c8e9ae82ae43d3", "https://www.example.com")]
    // Appendix C.6.3: the one that exercises the widest spread of symbols.
    [InlineData(
        "94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007",
        "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1")]
    public void Rfc_examples_decode_to_their_stated_values(string hex, string expected)
    {
        var decoded = HpackHuffman.Decode(Convert.FromHexString(hex));

        Assert.NotNull(decoded);
        Assert.Equal(expected, Encoding.ASCII.GetString(decoded!));
    }

    [Fact]
    public void Every_byte_value_round_trips_through_its_own_code()
    {
        // Covers the 128-255 range, which the RFC's ASCII-only examples never touch and
        // where a transcription error would otherwise go unnoticed until some header
        // carried a non-ASCII byte.
        for (var value = 0; value < 256; value++)
        {
            var encoded = HpackHuffmanEncoder.Encode([(byte)value]);
            var decoded = HpackHuffman.Decode(encoded);

            Assert.NotNull(decoded);
            Assert.Equal([(byte)value], decoded!);
        }
    }

    [Fact]
    public void A_longer_sequence_of_every_byte_round_trips()
    {
        // One symbol at a time always ends on a pad; a long run exercises codes that
        // straddle byte boundaries, which is where an off-by-one in the bit accounting
        // shows up.
        var all = new byte[256];
        for (var i = 0; i < all.Length; i++)
        {
            all[i] = (byte)i;
        }

        var decoded = HpackHuffman.Decode(HpackHuffmanEncoder.Encode(all));

        Assert.NotNull(decoded);
        Assert.Equal(all, decoded!);
    }

    [Fact]
    public void Padding_longer_than_a_byte_is_rejected()
    {
        // A whole byte of padding is malformed per the RFC. Accepting it would mean
        // accepting a truncated string as complete.
        Assert.Null(HpackHuffman.Decode([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]));
    }

    [Fact]
    public void Padding_that_is_not_all_ones_is_rejected()
    {
        // "www" followed by zero bits rather than the required ones.
        var encoded = HpackHuffmanEncoder.Encode("www"u8.ToArray());
        encoded[^1] &= 0xf0;

        Assert.Null(HpackHuffman.Decode(encoded));
    }
}

/// <summary>
/// A Huffman encoder, built only so the decoder can be tested against every byte value.
///
/// Deliberately a test-only mirror: it derives its codes the same canonical way the
/// decoder does, so a shared misunderstanding of the <em>table</em> would not be caught by
/// a round trip. That is what the Kraft check and the RFC vectors are for. What a round
/// trip does catch is bit-level accounting errors, which are a separate and likelier bug.
/// </summary>
internal static class HpackHuffmanEncoder
{
    private static readonly byte[] CodeLengths = ReadLengths();

    private static readonly uint[] Codes = BuildCodes();

    public static byte[] Encode(byte[] input)
    {
        var bits = new List<bool>();

        foreach (var b in input)
        {
            var length = CodeLengths[b];
            var code = Codes[b];

            for (var i = length - 1; i >= 0; i--)
            {
                bits.Add(((code >> i) & 1) != 0);
            }
        }

        // Pad to a byte boundary with ones, as the RFC requires.
        while (bits.Count % 8 != 0)
        {
            bits.Add(true);
        }

        var output = new byte[bits.Count / 8];

        for (var i = 0; i < bits.Count; i++)
        {
            if (bits[i])
            {
                output[i / 8] |= (byte)(0x80 >> (i % 8));
            }
        }

        return output;
    }

    /// <summary>
    /// The decoder's own length table, read through reflection so the two cannot drift
    /// apart. Keeping a second copy here would make a round-trip test pass while the
    /// product's table was wrong.
    /// </summary>
    private static byte[] ReadLengths()
    {
        var field = typeof(HpackHuffman).GetField(
            "CodeLengths",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);

        return (byte[])field!.GetValue(null)!;
    }

    private static uint[] BuildCodes()
    {
        const int maxLength = 30;
        var codes = new uint[CodeLengths.Length];
        var code = 0u;

        for (var length = 1; length <= maxLength; length++)
        {
            var assigned = 0;

            for (var symbol = 0; symbol < CodeLengths.Length; symbol++)
            {
                if (CodeLengths[symbol] == length)
                {
                    codes[symbol] = code + (uint)assigned;
                    assigned++;
                }
            }

            code = (code + (uint)assigned) << 1;
        }

        return codes;
    }
}
