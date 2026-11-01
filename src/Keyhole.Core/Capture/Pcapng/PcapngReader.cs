using System.Buffers.Binary;
using System.Text;

namespace Keyhole.Core.Capture.Pcapng;

/// <summary>
/// Reads back a pcapng file: its packets, their adapters' link types, and any TLS secrets
/// embedded in it.
///
/// The decoder works from the file rather than from the live capture, which means a
/// session can be decoded again later, and means decoding cannot slow down or break a
/// recording in progress. It also means the file is the single source of truth: if
/// Wireshark and Keyhole disagree about a capture, they are at least disagreeing about the
/// same bytes.
///
/// Only the blocks Keyhole writes are understood. Anything else is skipped by its declared
/// length, which is what makes pcapng extensible and what lets this reader survive a file
/// another tool has touched.
/// </summary>
public static class PcapngReader
{
    /// <summary>
    /// Walks a capture file.
    /// </summary>
    /// <returns>
    /// The packets in file order, plus the TLS secrets found along the way. Streamed, so a
    /// 500 MB capture does not have to fit in memory.
    /// </returns>
    public static IEnumerable<PcapngRecord> Read(string path)
    {
        using var stream = new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 64 * 1024);

        foreach (var record in Read(stream))
        {
            yield return record;
        }
    }

    public static IEnumerable<PcapngRecord> Read(Stream stream)
    {
        var header = new byte[8];
        var trailer = new byte[4];

        // Interface ids are assigned in the order their blocks appear, and every packet
        // references one. Without this the link type is unknown and the frame cannot be
        // parsed at all.
        var linkTypes = new List<PcapngLinkType>();

        var bigEndian = false;
        var sawSectionHeader = false;

        while (true)
        {
            if (stream.ReadAtLeast(header, 8, throwOnEndOfStream: false) < 8)
            {
                break;
            }

            var blockType = BinaryPrimitives.ReadUInt32LittleEndian(header);

            if (blockType == PcapngBlocks.BlockSectionHeader)
            {
                // A new section resets everything: its own endianness, and its own
                // interface numbering.
                sawSectionHeader = true;
                linkTypes.Clear();
            }
            else if (!sawSectionHeader)
            {
                // Not a pcapng file, or not one starting where we think it does.
                yield break;
            }

            var totalLength = ReadLength(header.AsSpan(4), bigEndian);

            if (totalLength < PcapngBlocks.FrameBytes ||
                totalLength % PcapngBlocks.Alignment != 0 ||
                totalLength > MaxBlockBytes)
            {
                yield break;
            }

            var body = new byte[totalLength - PcapngBlocks.FrameBytes];
            if (stream.ReadAtLeast(body, body.Length, throwOnEndOfStream: false) < body.Length)
            {
                yield break;
            }

            // The trailing length repeat, which this reader does not need but must consume.
            //
            // Into its own four-byte buffer, not into the eight-byte header buffer:
            // ReadAtLeast reads at least the minimum but up to the buffer's length, so
            // reusing the larger buffer here swallows the next block's type field as well.
            if (stream.ReadAtLeast(trailer, 4, throwOnEndOfStream: false) < 4)
            {
                yield break;
            }

            switch (blockType)
            {
                case PcapngBlocks.BlockSectionHeader:
                    // The byte-order magic reads as its own mirror image when the section
                    // was written big-endian, which is how a reader detects it.
                    bigEndian = body.Length >= 4 &&
                                BinaryPrimitives.ReadUInt32LittleEndian(body) != PcapngBlocks.ByteOrderMagic;
                    break;

                case PcapngBlocks.BlockInterfaceDescription when body.Length >= 2:
                    linkTypes.Add((PcapngLinkType)ReadUInt16(body, 0, bigEndian));
                    break;

                case PcapngBlocks.BlockEnhancedPacket when body.Length >= 20:
                {
                    var interfaceId = (int)ReadUInt32(body, 0, bigEndian);
                    var high = ReadUInt32(body, 4, bigEndian);
                    var low = ReadUInt32(body, 8, bigEndian);
                    var captured = (int)ReadUInt32(body, 12, bigEndian);
                    var original = (int)ReadUInt32(body, 16, bigEndian);

                    // A length claiming more than the block holds is a corrupt or
                    // truncated capture. Clamp rather than throw: the packets already read
                    // are still worth decoding.
                    if (captured < 0 || 20 + captured > body.Length)
                    {
                        captured = Math.Max(0, body.Length - 20);
                    }

                    var linkType = interfaceId >= 0 && interfaceId < linkTypes.Count
                        ? linkTypes[interfaceId]
                        : PcapngLinkType.Ethernet;

                    var microseconds = ((ulong)high << 32) | low;

                    yield return PcapngRecord.Packet(
                        DateTimeOffset.UnixEpoch.AddTicks((long)microseconds * TicksPerMicrosecond),
                        new ReadOnlyMemory<byte>(body, 20, captured),
                        original,
                        linkType);

                    break;
                }

                case PcapngBlocks.BlockDecryptionSecrets when body.Length >= 8:
                {
                    var secretsType = ReadUInt32(body, 0, bigEndian);
                    var length = (int)ReadUInt32(body, 4, bigEndian);

                    if (secretsType == PcapngBlocks.SecretsTypeTlsKeyLog &&
                        length >= 0 && 8 + length <= body.Length)
                    {
                        yield return PcapngRecord.Secrets(
                            Encoding.UTF8.GetString(body, 8, length));
                    }

                    break;
                }
            }
        }
    }

    private const long TicksPerMicrosecond = TimeSpan.TicksPerMillisecond / 1000;

    /// <summary>
    /// A ceiling on one block. pcapng allows larger, but a value this big in a file
    /// Keyhole wrote means a corrupt length rather than a real block, and allocating on
    /// its word would be a denial of service against the decoder.
    /// </summary>
    private const uint MaxBlockBytes = 64 * 1024 * 1024;

    private static uint ReadLength(ReadOnlySpan<byte> span, bool bigEndian) =>
        bigEndian
            ? BinaryPrimitives.ReadUInt32BigEndian(span)
            : BinaryPrimitives.ReadUInt32LittleEndian(span);

    private static ushort ReadUInt16(byte[] body, int offset, bool bigEndian) =>
        bigEndian
            ? BinaryPrimitives.ReadUInt16BigEndian(body.AsSpan(offset))
            : BinaryPrimitives.ReadUInt16LittleEndian(body.AsSpan(offset));

    private static uint ReadUInt32(byte[] body, int offset, bool bigEndian) =>
        bigEndian
            ? BinaryPrimitives.ReadUInt32BigEndian(body.AsSpan(offset))
            : BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(offset));
}

/// <summary>
/// One thing found in a capture file: either a packet or the session's TLS secrets.
///
/// A single stream of both rather than two passes, because the decoder needs the secrets
/// before the packets they unlock — and in a file Keyhole finished, that is exactly the
/// order they appear in.
/// </summary>
public sealed record PcapngRecord
{
    public required PcapngRecordKind Kind { get; init; }

    public DateTimeOffset Timestamp { get; init; }

    public ReadOnlyMemory<byte> Frame { get; init; }

    public int OriginalLength { get; init; }

    public PcapngLinkType LinkType { get; init; }

    /// <summary>NSS keylog text, for a <see cref="PcapngRecordKind.Secrets"/> record.</summary>
    public string? Keylog { get; init; }

    public static PcapngRecord Packet(
        DateTimeOffset timestamp,
        ReadOnlyMemory<byte> frame,
        int originalLength,
        PcapngLinkType linkType) => new()
    {
        Kind = PcapngRecordKind.Packet,
        Timestamp = timestamp,
        Frame = frame,
        OriginalLength = originalLength,
        LinkType = linkType,
    };

    public static PcapngRecord Secrets(string keylog) => new()
    {
        Kind = PcapngRecordKind.Secrets,
        Keylog = keylog,
    };
}

public enum PcapngRecordKind
{
    Packet,
    Secrets,
}
