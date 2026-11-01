using System.Buffers.Binary;
using System.Text;
using Keyhole.Core.Capture.Pcapng;

namespace Keyhole.Tests;

public class PcapngWriterTests
{
    [Fact]
    public void A_fresh_file_starts_with_a_section_header()
    {
        var bytes = Write(_ => { });

        Assert.Equal(0x0A0D0D0Au, BinaryPrimitives.ReadUInt32LittleEndian(bytes));

        // The byte-order magic sits right after the type and length, and is how a reader
        // decides the endianness of every other field in the section.
        Assert.Equal(0x1A2B3C4Du, BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(8)));
    }

    [Fact]
    public void Every_block_is_framed_and_aligned()
    {
        var bytes = Write(writer =>
        {
            var ethernet = writer.AddInterface(PcapngLinkType.Ethernet, "Test adapter");
            writer.WritePacket(ethernet, DateTimeOffset.UtcNow, new byte[60]);

            // 61 bytes needs three bytes of padding; an unpadded body would leave every
            // following block misaligned and unreadable.
            writer.WritePacket(ethernet, DateTimeOffset.UtcNow, new byte[61]);
        });

        var types = WalkBlocks(bytes);

        Assert.Equal(
            [0x0A0D0D0A, 0x00000001, 0x00000006, 0x00000006],
            types);
    }

    [Fact]
    public void The_length_is_repeated_at_both_ends_of_a_block()
    {
        // This is what lets a reader walk a capture backwards, and it is the first thing
        // a malformed writer gets wrong.
        var bytes = Write(writer => writer.AddInterface(PcapngLinkType.Ethernet));

        var offset = 0;
        while (offset < bytes.Length)
        {
            var length = (int)BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset + 4));
            var trailing = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset + length - 4));

            Assert.Equal((uint)length, trailing);
            offset += length;
        }

        Assert.Equal(bytes.Length, offset);
    }

    [Fact]
    public void Packets_for_an_undeclared_interface_are_refused()
    {
        using var stream = new MemoryStream();
        using var writer = new PcapngWriter(stream);

        // Writing a packet against an interface id that was never described would produce
        // a file every reader mis-parses, with no error to explain it.
        Assert.Throws<ArgumentOutOfRangeException>(
            () => writer.WritePacket(0, DateTimeOffset.UtcNow, new byte[10]));
    }

    [Fact]
    public void Tls_secrets_become_a_decryption_secrets_block()
    {
        const string keylog = "CLIENT_HANDSHAKE_TRAFFIC_SECRET abc123 deadbeef\n";

        var bytes = Write(writer => writer.WriteTlsSecrets(keylog));
        var types = WalkBlocks(bytes);

        Assert.Contains(0x0000000Au, types);

        // "TLSK": the secrets type that tells a reader these are NSS key log lines.
        var secrets = FindBlockBody(bytes, 0x0000000A);
        Assert.Equal(0x544C534Bu, BinaryPrimitives.ReadUInt32LittleEndian(secrets));

        var length = (int)BinaryPrimitives.ReadUInt32LittleEndian(secrets[4..]);
        Assert.Equal(keylog.Length, length);
        Assert.Equal(keylog, Encoding.UTF8.GetString(secrets.Slice(8, length)));
    }

    [Fact]
    public void An_empty_keylog_writes_no_block()
    {
        // A session whose application uses Schannel writes no secrets. An empty secrets
        // block would claim otherwise.
        var bytes = Write(writer => writer.WriteTlsSecrets(""));

        Assert.DoesNotContain(0x0000000Au, WalkBlocks(bytes));
    }

    [Fact]
    public void Byte_count_matches_the_file()
    {
        using var stream = new MemoryStream();

        long reported;
        using (var writer = new PcapngWriter(stream, ownsStream: false))
        {
            var id = writer.AddInterface(PcapngLinkType.Ethernet);
            writer.WritePacket(id, DateTimeOffset.UtcNow, new byte[1400]);
            writer.WritePacket(id, DateTimeOffset.UtcNow, new byte[1400]);
            reported = writer.BytesWritten;

            Assert.Equal(2, writer.PacketsWritten);
        }

        // The size cap is enforced against this number, so a count that drifts from the
        // file would let a capture overrun its limit.
        Assert.Equal(stream.Length, reported);
    }

    [Fact]
    public void Timestamps_survive_the_round_trip()
    {
        var when = new DateTimeOffset(2026, 11, 1, 12, 34, 56, 789, TimeSpan.Zero)
            .AddMicroseconds(123);

        var bytes = Write(writer =>
        {
            var id = writer.AddInterface(PcapngLinkType.Ethernet);
            writer.WritePacket(id, when, new byte[4]);
        });

        var packet = FindBlockBody(bytes, 0x00000006);

        // Microseconds since the epoch, high word first.
        var high = BinaryPrimitives.ReadUInt32LittleEndian(packet[4..]);
        var low = BinaryPrimitives.ReadUInt32LittleEndian(packet[8..]);
        var microseconds = ((ulong)high << 32) | low;

        Assert.Equal(
            (ulong)(when.ToUnixTimeMilliseconds() * 1000 + 123),
            microseconds);
    }

    [Fact]
    public void Truncated_packets_report_their_wire_length()
    {
        var bytes = Write(writer =>
        {
            var id = writer.AddInterface(PcapngLinkType.Ethernet, snapLength: 128);
            writer.WritePacket(id, DateTimeOffset.UtcNow, new byte[128], originalLength: 1514);
        });

        var packet = FindBlockBody(bytes, 0x00000006);

        // Captured and original lengths both matter: without the second, a reader
        // describes a truncated packet as a short one.
        Assert.Equal(128u, BinaryPrimitives.ReadUInt32LittleEndian(packet[12..]));
        Assert.Equal(1514u, BinaryPrimitives.ReadUInt32LittleEndian(packet[16..]));
    }

    private static byte[] Write(Action<PcapngWriter> write)
    {
        using var stream = new MemoryStream();

        using (var writer = new PcapngWriter(stream, ownsStream: false))
        {
            write(writer);
        }

        return stream.ToArray();
    }

    /// <summary>
    /// Walks the file by block length alone — the way a reader does — so a block whose
    /// length does not match its contents shows up as a parse failure here.
    /// </summary>
    private static List<uint> WalkBlocks(byte[] bytes)
    {
        var types = new List<uint>();
        var offset = 0;

        while (offset + 8 <= bytes.Length)
        {
            var type = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset));
            var length = (int)BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset + 4));

            Assert.True(length >= 12, $"Block at {offset} claims {length} bytes.");
            Assert.Equal(0, length % 4);
            Assert.True(offset + length <= bytes.Length, $"Block at {offset} runs past the end.");

            types.Add(type);
            offset += length;
        }

        Assert.Equal(bytes.Length, offset);
        return types;
    }

    private static ReadOnlySpan<byte> FindBlockBody(byte[] bytes, uint blockType)
    {
        var offset = 0;

        while (offset + 8 <= bytes.Length)
        {
            var type = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset));
            var length = (int)BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset + 4));

            if (type == blockType)
            {
                return bytes.AsSpan(offset + 8, length - 12);
            }

            offset += length;
        }

        Assert.Fail($"No block of type 0x{blockType:X8} in the file.");
        return default;
    }
}

public class PcapngSecretsInjectorTests
{
    [Fact]
    public void Secrets_land_ahead_of_the_packets()
    {
        var path = NewCapture(writer =>
        {
            var id = writer.AddInterface(PcapngLinkType.Ethernet);
            writer.WritePacket(id, DateTimeOffset.UtcNow, new byte[64]);
            writer.WritePacket(id, DateTimeOffset.UtcNow, new byte[64]);
        });

        try
        {
            var result = PcapngSecretsInjector.Inject(path, "CLIENT_RANDOM aaa bbb\n");

            Assert.True(result.Succeeded);
            Assert.Null(result.Detail);

            var types = BlockTypes(path);

            // Order is the whole point: a reader applies secrets as it walks the file, so
            // a block after the packets arrives too late to decrypt them.
            var secrets = types.IndexOf(0x0000000Au);
            var firstPacket = types.IndexOf(0x00000006u);

            Assert.True(secrets >= 0, "No secrets block was written.");
            Assert.True(secrets < firstPacket, "The secrets block must precede the packets.");

            // The interface description must still come first, or the packets reference an
            // interface the reader has not seen.
            Assert.True(types.IndexOf(0x00000001u) < secrets);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void A_capture_with_no_packets_still_gets_its_secrets()
    {
        var path = NewCapture(writer => writer.AddInterface(PcapngLinkType.Ethernet));

        try
        {
            Assert.True(PcapngSecretsInjector.Inject(path, "CLIENT_RANDOM aaa bbb\n").Succeeded);
            Assert.Contains(0x0000000Au, BlockTypes(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Packets_survive_the_rewrite_byte_for_byte()
    {
        var payload = new byte[300];
        Random.Shared.NextBytes(payload);

        var path = NewCapture(writer =>
        {
            var id = writer.AddInterface(PcapngLinkType.Ethernet);
            for (var i = 0; i < 50; i++)
            {
                writer.WritePacket(id, DateTimeOffset.UtcNow, payload);
            }
        });

        try
        {
            Assert.True(PcapngSecretsInjector.Inject(path, "CLIENT_RANDOM aaa bbb\n").Succeeded);

            var types = BlockTypes(path);
            Assert.Equal(50, types.Count(t => t == 0x00000006u));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void An_empty_keylog_leaves_the_capture_alone()
    {
        var path = NewCapture(writer =>
        {
            var id = writer.AddInterface(PcapngLinkType.Ethernet);
            writer.WritePacket(id, DateTimeOffset.UtcNow, new byte[64]);
        });

        try
        {
            var before = File.ReadAllBytes(path);

            var result = PcapngSecretsInjector.Inject(path, "");

            Assert.False(result.Succeeded);
            Assert.NotNull(result.Detail);

            // Nothing to inject must mean nothing is touched, not a rewritten file.
            Assert.Equal(before, File.ReadAllBytes(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void A_file_that_is_not_pcapng_is_left_intact()
    {
        var path = Path.Combine(Path.GetTempPath(), $"keyhole-bogus-{Guid.NewGuid():N}.pcapng");
        var original = "this is not a capture"u8.ToArray();
        File.WriteAllBytes(path, original);

        try
        {
            var result = PcapngSecretsInjector.Inject(path, "CLIENT_RANDOM aaa bbb\n");

            Assert.False(result.Succeeded);
            Assert.NotNull(result.Detail);

            // Replacing it with a half-written copy would destroy whatever it really was.
            Assert.Equal(original, File.ReadAllBytes(path));
            Assert.False(File.Exists(path + ".rewriting"));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void A_missing_capture_is_not_an_error()
    {
        // A session where Npcap was unavailable has a keylog but no pcap. That is a normal
        // outcome and must not read as a failure.
        var result = PcapngSecretsInjector.Inject(
            Path.Combine(Path.GetTempPath(), $"keyhole-absent-{Guid.NewGuid():N}.pcapng"),
            "CLIENT_RANDOM aaa bbb\n");

        Assert.False(result.Succeeded);
        Assert.NotNull(result.Detail);
    }

    private static string NewCapture(Action<PcapngWriter> write)
    {
        var path = Path.Combine(Path.GetTempPath(), $"keyhole-test-{Guid.NewGuid():N}.pcapng");

        using (var writer = PcapngWriter.Create(path))
        {
            write(writer);
        }

        return path;
    }

    private static List<uint> BlockTypes(string path)
    {
        var bytes = File.ReadAllBytes(path);
        var types = new List<uint>();
        var offset = 0;

        while (offset + 8 <= bytes.Length)
        {
            types.Add(BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset)));
            var length = (int)BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset + 4));

            Assert.True(length >= 12 && offset + length <= bytes.Length);
            offset += length;
        }

        Assert.Equal(bytes.Length, offset);
        return types;
    }
}
