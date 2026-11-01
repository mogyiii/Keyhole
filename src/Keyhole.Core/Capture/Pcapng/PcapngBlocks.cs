using System.Buffers;
using System.Buffers.Binary;
using System.Text;

namespace Keyhole.Core.Capture.Pcapng;

/// <summary>
/// The framing every pcapng block shares, plus the one block both the writer and the
/// rewriter need to emit.
///
/// Shared because the secrets block is written from two places — appended by the live
/// writer, and inserted ahead of the packets by the rewriter — and two copies of the
/// layout would be two chances to get the padding wrong.
/// </summary>
internal static class PcapngBlocks
{
    /// <summary>Block lengths and bodies are always a multiple of four bytes.</summary>
    internal const int Alignment = 4;

    /// <summary>Type, plus the total length written at both ends.</summary>
    internal const int FrameBytes = 12;

    private static ReadOnlySpan<byte> Padding => [0, 0, 0, 0];

    /// <summary>
    /// Writes one block: type, total length, body, total length again. The length appears
    /// twice so that a reader can walk the file backwards as well as forwards.
    /// </summary>
    /// <returns>Bytes written, so a caller enforcing a size cap can account for them.</returns>
    internal static int WriteBlock(Stream stream, uint blockType, ReadOnlySpan<byte> body)
    {
        var totalLength = FrameBytes + body.Length;

        Span<byte> header = stackalloc byte[8];
        BinaryPrimitives.WriteUInt32LittleEndian(header, blockType);
        BinaryPrimitives.WriteUInt32LittleEndian(header[4..], (uint)totalLength);
        stream.Write(header);

        stream.Write(body);

        Span<byte> trailer = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(trailer, (uint)totalLength);
        stream.Write(trailer);

        return totalLength;
    }

    /// <summary>
    /// Writes a Decryption Secrets Block carrying an NSS-format TLS key log.
    ///
    /// This is the block that makes a Keyhole capture self-contained: Wireshark reads the
    /// secrets out of the file itself, so there is no keylog path to configure and no way
    /// for the two halves to drift apart.
    /// </summary>
    internal static int WriteTlsSecrets(Stream stream, string keylogContents)
    {
        var secrets = Encoding.UTF8.GetBytes(keylogContents);

        var body = new ArrayBufferWriter<byte>();
        WriteUInt32(body, SecretsTypeTlsKeyLog);
        WriteUInt32(body, (uint)secrets.Length);
        body.Write(secrets);
        Pad(body, secrets.Length);

        return WriteBlock(stream, BlockDecryptionSecrets, body.WrittenSpan);
    }

    /// <summary>Pads a body out to the four-byte alignment pcapng requires.</summary>
    internal static void Pad(ArrayBufferWriter<byte> body, int length)
    {
        var remainder = length % Alignment;
        if (remainder != 0)
        {
            body.Write(Padding[..(Alignment - remainder)]);
        }
    }

    internal static void WriteUInt16(ArrayBufferWriter<byte> writer, ushort value)
    {
        BinaryPrimitives.WriteUInt16LittleEndian(writer.GetSpan(2), value);
        writer.Advance(2);
    }

    internal static void WriteUInt32(ArrayBufferWriter<byte> writer, uint value)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(writer.GetSpan(4), value);
        writer.Advance(4);
    }

    internal static void WriteUInt64(ArrayBufferWriter<byte> writer, ulong value)
    {
        BinaryPrimitives.WriteUInt64LittleEndian(writer.GetSpan(8), value);
        writer.Advance(8);
    }

    // Block types from the pcapng specification.
    internal const uint BlockSectionHeader = 0x0A0D0D0A;
    internal const uint BlockInterfaceDescription = 0x00000001;
    internal const uint BlockEnhancedPacket = 0x00000006;
    internal const uint BlockDecryptionSecrets = 0x0000000A;

    internal const uint ByteOrderMagic = 0x1A2B3C4D;

    /// <summary>"TLSK" — an NSS key log, which is exactly what SSLKEYLOGFILE produces.</summary>
    internal const uint SecretsTypeTlsKeyLog = 0x544C534B;
}
