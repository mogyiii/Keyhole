using System.Buffers;
using System.Text;

namespace Keyhole.Core.Capture.Pcapng;

/// <summary>
/// Writes a pcapng file: a section header, one interface description per adapter, and an
/// enhanced packet block per packet.
///
/// Hand-rolled rather than taken from a library because of one block type. pcapng can
/// carry a Decryption Secrets Block, so the TLS keylog can live <em>inside</em> the
/// capture file — open it in Wireshark and the traffic is already decrypted, with no
/// preference to point at a keylog on disk. Classic pcap has nowhere to put that, and the
/// capture libraries only write classic pcap.
///
/// The file is valid at every point: blocks are complete when written and the header never
/// needs revisiting. A capture killed mid-session still opens.
/// </summary>
public sealed class PcapngWriter : IDisposable
{
    private readonly Stream _stream;
    private readonly bool _ownsStream;
    private int _interfaces;

    public PcapngWriter(Stream stream, bool ownsStream = true, string? applicationName = null)
    {
        _stream = stream;
        _ownsStream = ownsStream;
        WriteSectionHeader(applicationName ?? "Keyhole");
    }

    public static PcapngWriter Create(string path, string? applicationName = null)
    {
        var stream = new FileStream(
            path, FileMode.Create, FileAccess.Write, FileShare.Read, bufferSize: 64 * 1024);

        return new PcapngWriter(stream, ownsStream: true, applicationName);
    }

    /// <summary>Bytes written so far, which is what a size cap is measured against.</summary>
    public long BytesWritten { get; private set; }

    /// <summary>Packets accepted into the file.</summary>
    public long PacketsWritten { get; private set; }

    /// <summary>
    /// Declares an adapter and returns the id its packets must carry.
    ///
    /// One block per adapter, because link types differ: Ethernet adapters and Npcap's
    /// loopback adapter frame packets differently, and a reader that is told the wrong one
    /// mis-parses every packet from it.
    /// </summary>
    public int AddInterface(PcapngLinkType linkType, string? name = null, int snapLength = 65535)
    {
        var options = new OptionWriter();

        if (!string.IsNullOrWhiteSpace(name))
        {
            options.AddString(OptionIfName, name);
        }

        options.AddString(OptionIfDescription, $"Captured by Keyhole on {linkType}");

        // if_tsresol: timestamps below are microseconds since the Unix epoch. The default
        // happens to be the same, but stating it removes any doubt for the reader.
        options.AddByte(OptionIfTsResol, 6);

        var body = new ArrayBufferWriter<byte>();
        PcapngBlocks.WriteUInt16(body, (ushort)linkType);
        PcapngBlocks.WriteUInt16(body, 0);                  // reserved
        PcapngBlocks.WriteUInt32(body, (uint)snapLength);
        options.CopyTo(body);

        BytesWritten += PcapngBlocks.WriteBlock(
            _stream, PcapngBlocks.BlockInterfaceDescription, body.WrittenSpan);

        return _interfaces++;
    }

    /// <summary>
    /// Writes one captured packet.
    /// </summary>
    /// <param name="interfaceId">Id returned by <see cref="AddInterface"/>.</param>
    /// <param name="timestamp">When the packet was seen.</param>
    /// <param name="data">The captured bytes, which may be shorter than the wire packet.</param>
    /// <param name="originalLength">
    /// The packet's length on the wire. Larger than <paramref name="data"/> when the
    /// snaplen truncated it; readers need both to say "truncated" rather than silently
    /// describing a short packet.
    /// </param>
    public void WritePacket(
        int interfaceId, DateTimeOffset timestamp, ReadOnlySpan<byte> data, int? originalLength = null)
    {
        if (interfaceId < 0 || interfaceId >= _interfaces)
        {
            throw new ArgumentOutOfRangeException(
                nameof(interfaceId),
                $"Interface {interfaceId} was never declared; call {nameof(AddInterface)} first.");
        }

        // Microseconds since the Unix epoch, split across two 32-bit words. pcapng has no
        // 64-bit field here: the halves are written as separate values, high first.
        var microseconds = (ulong)(timestamp.ToUnixTimeMilliseconds() * 1000L + timestamp.Microsecond);

        var body = new ArrayBufferWriter<byte>();
        PcapngBlocks.WriteUInt32(body, (uint)interfaceId);
        PcapngBlocks.WriteUInt32(body, (uint)(microseconds >> 32));
        PcapngBlocks.WriteUInt32(body, (uint)(microseconds & 0xFFFFFFFF));
        PcapngBlocks.WriteUInt32(body, (uint)data.Length);
        PcapngBlocks.WriteUInt32(body, (uint)(originalLength ?? data.Length));
        body.Write(data);
        PcapngBlocks.Pad(body, data.Length);

        BytesWritten += PcapngBlocks.WriteBlock(
            _stream, PcapngBlocks.BlockEnhancedPacket, body.WrittenSpan);

        PacketsWritten++;
    }

    /// <summary>
    /// Writes the TLS secrets collected for this session into the file itself.
    ///
    /// Appending works for a file a reader opens whole, but secrets placed <em>before</em>
    /// the packets is what a sequential reader wants; see
    /// <see cref="PcapngSecretsInjector"/>, which does that at the end of a session.
    /// </summary>
    public void WriteTlsSecrets(string keylogContents)
    {
        if (string.IsNullOrWhiteSpace(keylogContents))
        {
            return;
        }

        BytesWritten += PcapngBlocks.WriteTlsSecrets(_stream, keylogContents);
    }

    public void Flush() => _stream.Flush();

    public void Dispose()
    {
        try
        {
            _stream.Flush();
        }
        catch (IOException)
        {
            // Nothing useful to do while tearing down; the file is as complete as it got.
        }

        if (_ownsStream)
        {
            _stream.Dispose();
        }
    }

    private void WriteSectionHeader(string applicationName)
    {
        var options = new OptionWriter();
        options.AddString(OptionShbOs, Environment.OSVersion.VersionString);
        options.AddString(OptionShbUserAppl, applicationName);

        var body = new ArrayBufferWriter<byte>();

        // The byte-order magic is what tells a reader the endianness of every field in the
        // section, including the lengths it needs to walk the file at all.
        PcapngBlocks.WriteUInt32(body, PcapngBlocks.ByteOrderMagic);
        PcapngBlocks.WriteUInt16(body, 1);   // major version
        PcapngBlocks.WriteUInt16(body, 0);   // minor version

        // Section length unknown: -1 means "to the end of the file", which is the only
        // honest answer while still capturing.
        PcapngBlocks.WriteUInt64(body, unchecked((ulong)-1L));

        options.CopyTo(body);

        BytesWritten += PcapngBlocks.WriteBlock(
            _stream, PcapngBlocks.BlockSectionHeader, body.WrittenSpan);
    }

    /// <summary>
    /// Accumulates a block's options and terminates them.
    ///
    /// Options are optional, but the terminator is not: a reader walks them until it finds
    /// opt_endofopt, so omitting it makes the block's tail look like another option.
    /// </summary>
    private sealed class OptionWriter
    {
        private readonly ArrayBufferWriter<byte> _buffer = new();
        private bool _any;

        public void AddString(ushort code, string value)
        {
            var bytes = Encoding.UTF8.GetBytes(value);

            // Options carry a 16-bit length, so an absurdly long value cannot be expressed.
            // Truncating is better than throwing: these are all descriptive.
            if (bytes.Length > ushort.MaxValue)
            {
                bytes = bytes[..ushort.MaxValue];
            }

            Add(code, bytes);
        }

        public void AddByte(ushort code, byte value) => Add(code, [value]);

        private void Add(ushort code, ReadOnlySpan<byte> value)
        {
            PcapngBlocks.WriteUInt16(_buffer, code);
            PcapngBlocks.WriteUInt16(_buffer, (ushort)value.Length);
            _buffer.Write(value);
            PcapngBlocks.Pad(_buffer, value.Length);
            _any = true;
        }

        public void CopyTo(ArrayBufferWriter<byte> body)
        {
            if (!_any)
            {
                return;
            }

            body.Write(_buffer.WrittenSpan);

            // opt_endofopt
            PcapngBlocks.WriteUInt16(body, 0);
            PcapngBlocks.WriteUInt16(body, 0);
        }
    }

    private const ushort OptionShbOs = 3;
    private const ushort OptionShbUserAppl = 4;
    private const ushort OptionIfName = 2;
    private const ushort OptionIfDescription = 3;
    private const ushort OptionIfTsResol = 9;
}

/// <summary>
/// The link types Keyhole writes. Values are libpcap's DLT numbers, which pcapng reuses.
/// </summary>
public enum PcapngLinkType : ushort
{
    /// <summary>DLT_NULL — a 4-byte address-family header. Npcap's loopback adapter.</summary>
    Null = 0,

    /// <summary>DLT_EN10MB — an Ethernet header. Every ordinary adapter.</summary>
    Ethernet = 1,

    /// <summary>DLT_RAW — a bare IP packet with no link header.</summary>
    Raw = 101,
}
