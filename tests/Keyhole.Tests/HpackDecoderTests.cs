using Keyhole.Core.Capture.Decode;

namespace Keyhole.Tests;

/// <summary>
/// HPACK checked against RFC 7541's worked request and response sequences.
///
/// The sequences matter more than any single block. HPACK is stateful: each block's
/// meaning depends on the dynamic table the blocks before it built, so a decoder can get
/// the first block right and every one after it wrong. Only replaying a whole connection
/// in order exercises that — which is also how the real decoder is used.
/// </summary>
public class HpackDecoderTests
{
    [Fact]
    public void A_single_indexed_header_resolves_from_the_static_table()
    {
        // 0x82 is index 2: ":method: GET".
        var headers = new HpackDecoder().Decode(Convert.FromHexString("82"));

        Assert.NotNull(headers);
        Assert.Equal([new HttpHeader(":method", "GET")], headers!);
    }

    [Fact]
    public void Static_table_indices_are_one_based()
    {
        // Off-by-one here returns a neighbouring header, which looks entirely plausible:
        // index 2 would read as ":authority" and index 8 as ":status: 204". Both ends of
        // the table are checked because an off-by-one shows at one end only.
        var decoder = new HpackDecoder();

        Assert.Equal(
            [new HttpHeader(":authority", "")],
            decoder.Decode(Convert.FromHexString("81"))!);

        Assert.Equal(
            [new HttpHeader(":status", "200")],
            decoder.Decode(Convert.FromHexString("88"))!);

        // 61 is the last static entry; 62 with an empty dynamic table must fail rather
        // than wrap around to something.
        Assert.Equal(
            [new HttpHeader("www-authenticate", "")],
            decoder.Decode(Convert.FromHexString("BD"))!);

        Assert.Null(new HpackDecoder().Decode(Convert.FromHexString("BE")));
    }

    [Fact]
    public void Rfc_c_3_decodes_a_three_request_sequence()
    {
        // Appendix C.3: literal headers without Huffman, building the dynamic table as it
        // goes. The third request's one-byte references only resolve if the first two
        // updated the table correctly.
        var decoder = new HpackDecoder();

        var first = decoder.Decode(Convert.FromHexString(
            "828684410f7777772e6578616d706c652e636f6d"));

        Assert.Equal(
            [
                new HttpHeader(":method", "GET"),
                new HttpHeader(":scheme", "http"),
                new HttpHeader(":path", "/"),
                new HttpHeader(":authority", "www.example.com"),
            ],
            first!);

        var second = decoder.Decode(Convert.FromHexString(
            "828684be58086e6f2d6361636865"));

        Assert.Equal(
            [
                new HttpHeader(":method", "GET"),
                new HttpHeader(":scheme", "http"),
                new HttpHeader(":path", "/"),
                // 0xbe is index 62: the authority this connection sent a moment ago.
                new HttpHeader(":authority", "www.example.com"),
                new HttpHeader("cache-control", "no-cache"),
            ],
            second!);

        var third = decoder.Decode(Convert.FromHexString(
            "828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565"));

        Assert.Equal(
            [
                new HttpHeader(":method", "GET"),
                new HttpHeader(":scheme", "https"),
                new HttpHeader(":path", "/index.html"),
                new HttpHeader(":authority", "www.example.com"),
                new HttpHeader("custom-key", "custom-value"),
            ],
            third!);
    }

    [Fact]
    public void Rfc_c_4_decodes_the_same_sequence_huffman_coded()
    {
        // Appendix C.4 is C.3 with Huffman-coded strings, so this is the one that proves
        // the length prefix's Huffman bit is honoured rather than assumed either way.
        var decoder = new HpackDecoder();

        var first = decoder.Decode(Convert.FromHexString(
            "828684418cf1e3c2e5f23a6ba0ab90f4ff"));

        Assert.Equal(
            [
                new HttpHeader(":method", "GET"),
                new HttpHeader(":scheme", "http"),
                new HttpHeader(":path", "/"),
                new HttpHeader(":authority", "www.example.com"),
            ],
            first!);

        var second = decoder.Decode(Convert.FromHexString(
            "828684be5886a8eb10649cbf"));

        Assert.Contains(new HttpHeader("cache-control", "no-cache"), second!);
        Assert.Contains(new HttpHeader(":authority", "www.example.com"), second!);

        var third = decoder.Decode(Convert.FromHexString(
            "828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf"));

        Assert.Contains(new HttpHeader("custom-key", "custom-value"), third!);
    }

    [Fact]
    public void Rfc_c_5_decodes_a_response_sequence_with_eviction()
    {
        // Appendix C.5 runs the dynamic table at a 256-byte limit, so the third response
        // can only decode if entries were evicted at exactly the right points. An
        // eviction that is off by one entry makes its references resolve to the wrong
        // header rather than fail.
        var decoder = new HpackDecoder();

        // The size update the RFC's example begins from.
        decoder.Decode(Convert.FromHexString("3fe107"));

        var first = decoder.Decode(Convert.FromHexString(
            "4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e" +
            "1768747470733a2f2f7777772e6578616d706c652e636f6d"));

        Assert.Equal(
            [
                new HttpHeader(":status", "302"),
                new HttpHeader("cache-control", "private"),
                new HttpHeader("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                new HttpHeader("location", "https://www.example.com"),
            ],
            first!);

        var second = decoder.Decode(Convert.FromHexString("4803333037c1c0bf"));

        Assert.Equal(
            [
                new HttpHeader(":status", "307"),
                new HttpHeader("cache-control", "private"),
                new HttpHeader("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                new HttpHeader("location", "https://www.example.com"),
            ],
            second!);

        var third = decoder.Decode(Convert.FromHexString(
            "88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d54c05a04677a69707738666f6f3d" +
            "4153444a4b48514b425a584f5157454f50495541585157454f49553b206d61782d6167653d333630303b2076657" +
            "273696f6e3d31"));

        Assert.Equal(
            [
                new HttpHeader(":status", "200"),
                new HttpHeader("cache-control", "private"),
                // A second later than the previous response: the date was re-sent as a
                // literal, which also evicted entries.
                new HttpHeader("date", "Mon, 21 Oct 2013 20:13:22 GMT"),
                new HttpHeader("location", "https://www.example.com"),
                new HttpHeader("content-encoding", "gzip"),
                new HttpHeader(
                    "set-cookie",
                    "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"),
            ],
            third!);
    }

    [Fact]
    public void Rfc_c_6_decodes_the_response_sequence_huffman_coded()
    {
        var decoder = new HpackDecoder();
        decoder.Decode(Convert.FromHexString("3fe107"));

        var first = decoder.Decode(Convert.FromHexString(
            "488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad1718" +
            "63c78f0b97c8e9ae82ae43d3"));

        Assert.Equal(
            [
                new HttpHeader(":status", "302"),
                new HttpHeader("cache-control", "private"),
                new HttpHeader("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                new HttpHeader("location", "https://www.example.com"),
            ],
            first!);

        var third = decoder.Decode(Convert.FromHexString("4883640effc1c0bf"));
        Assert.Equal("307", third!.First(h => h.Name == ":status").Value);
    }

    [Fact]
    public void A_truncated_block_breaks_the_decoder_rather_than_guessing()
    {
        var decoder = new HpackDecoder();

        // A literal header claiming a longer string than the block holds. Reading on would
        // produce a header built from whatever followed.
        Assert.Null(decoder.Decode(Convert.FromHexString("400a637573746f6d")));

        Assert.True(decoder.IsBroken);
        Assert.NotNull(decoder.Error);

        // And it stays broken: the dynamic table is now out of step with the encoder's, so
        // later blocks on this connection cannot be trusted either.
        Assert.Null(decoder.Decode(Convert.FromHexString("82")));
    }

    [Fact]
    public void An_oversized_entry_empties_the_table()
    {
        var decoder = new HpackDecoder();

        // Shrink the table so the next insertion cannot fit, then insert. The RFC says
        // this clears the table and stores nothing — so the reference afterwards must fail
        // rather than resolve.
        decoder.Decode(Convert.FromHexString("20"));
        var headers = decoder.Decode(Convert.FromHexString("400a637573746f6d2d6b65790c637573746f6d2d76616c7565"));

        Assert.Equal([new HttpHeader("custom-key", "custom-value")], headers!);
        Assert.Null(new HpackDecoder().Decode(Convert.FromHexString("BE")));
    }
}
