using System.Net;
using Keyhole.Core.Capture.Pcapng;
using PacketDotNet;

namespace Keyhole.Core.Capture.Recording;

/// <summary>
/// What a captured frame turns out to contain, once its link, IP and transport headers
/// have been read.
///
/// Both halves of M8 need this. The recorder needs the ports, to decide whether a packet
/// belongs to the application being captured; the decoder needs the addresses, sequence
/// number and payload, to rebuild the byte stream a TLS session was carried over. Parsing
/// once and sharing the result keeps the two from disagreeing about what a packet is.
/// </summary>
/// <param name="Protocol">TCP or UDP.</param>
/// <param name="Source">Sending address and port.</param>
/// <param name="Destination">Receiving address and port.</param>
/// <param name="SequenceNumber">
/// TCP sequence number of the first payload byte. Zero for UDP, which has no ordering.
/// </param>
/// <param name="Payload">The transport payload, which is empty for a bare ACK or handshake.</param>
/// <param name="IsSyn">Set on a connection's opening packets, which establish the sequence base.</param>
/// <param name="IsAck">
/// Set on everything after the opening SYN. Carried because SYN alone does not identify
/// the client: the server answers with SYN and ACK together, so only a SYN <em>without</em>
/// an ACK marks the side that opened the connection — and which side is the client decides
/// which TLS key opens which direction.
/// </param>
/// <param name="IsFin">Set when this direction is finished sending.</param>
/// <param name="IsReset">Set when the connection was aborted.</param>
public readonly record struct TransportSegment(
    ProtocolType Protocol,
    IPEndPoint Source,
    IPEndPoint Destination,
    uint SequenceNumber,
    ReadOnlyMemory<byte> Payload,
    bool IsSyn,
    bool IsAck,
    bool IsFin,
    bool IsReset)
{
    /// <summary>
    /// True only for the segment that opened the connection. The one reliable marker of
    /// which endpoint is the client.
    /// </summary>
    public bool IsConnectionOpener => IsSyn && !IsAck;

    /// <summary>
    /// Identifies the connection this segment belongs to, without regard to direction.
    /// Both directions of one conversation produce the same key, which is what lets the
    /// decoder pair a request with its response.
    /// </summary>
    public ConversationKey Conversation => ConversationKey.For(Source, Destination);

    /// <summary>
    /// Reads the headers of one captured frame.
    /// </summary>
    /// <returns>
    /// Null when the frame is not IP-over-TCP/UDP — ARP, IPv6 extension chains Keyhole
    /// does not follow, truncated captures. Those are skipped rather than reported: a busy
    /// adapter carries plenty of them and none is an error.
    /// </returns>
    public static TransportSegment? TryRead(ReadOnlyMemory<byte> frame, PcapngLinkType linkType)
    {
        try
        {
            var packet = Packet.ParsePacket(ToLinkLayer(linkType), frame.ToArray());

            var ip = packet.Extract<IPPacket>();
            if (ip is null)
            {
                return null;
            }

            if (packet.Extract<TcpPacket>() is { } tcp)
            {
                return new TransportSegment(
                    ProtocolType.Tcp,
                    new IPEndPoint(ip.SourceAddress, tcp.SourcePort),
                    new IPEndPoint(ip.DestinationAddress, tcp.DestinationPort),
                    tcp.SequenceNumber,
                    tcp.PayloadData ?? ReadOnlyMemory<byte>.Empty,
                    tcp.Synchronize,
                    tcp.Acknowledgment,
                    tcp.Finished,
                    tcp.Reset);
            }

            if (packet.Extract<UdpPacket>() is { } udp)
            {
                return new TransportSegment(
                    ProtocolType.Udp,
                    new IPEndPoint(ip.SourceAddress, udp.SourcePort),
                    new IPEndPoint(ip.DestinationAddress, udp.DestinationPort),
                    0,
                    udp.PayloadData ?? ReadOnlyMemory<byte>.Empty,
                    false,
                    false,
                    false,
                    false);
            }

            return null;
        }
        catch (Exception)
        {
            // A truncated or malformed frame is normal on a live adapter. Dropping it is
            // the right answer; throwing would end the capture over one bad packet.
            return null;
        }
    }

    private static LinkLayers ToLinkLayer(PcapngLinkType linkType) => linkType switch
    {
        PcapngLinkType.Ethernet => LinkLayers.Ethernet,
        PcapngLinkType.Null => LinkLayers.Null,
        PcapngLinkType.Raw => LinkLayers.Raw,
        _ => LinkLayers.Ethernet,
    };
}

/// <summary>Transport protocols Keyhole records.</summary>
public enum ProtocolType
{
    Tcp,
    Udp,
}

/// <summary>
/// A direction-independent identity for one conversation.
///
/// The endpoints are stored in a fixed order so that a packet and its reply hash the same
/// way. The same reasoning fixed the TCP download counts during M2's live verification:
/// keying on the pair as sent splits one conversation into two halves that never meet.
/// </summary>
public readonly record struct ConversationKey(string Low, string High)
{
    public static ConversationKey For(IPEndPoint a, IPEndPoint b)
    {
        var first = a.ToString();
        var second = b.ToString();

        return string.CompareOrdinal(first, second) <= 0
            ? new ConversationKey(first, second)
            : new ConversationKey(second, first);
    }

    public override string ToString() => $"{Low} <-> {High}";
}
