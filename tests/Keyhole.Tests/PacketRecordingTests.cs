using System.Buffers.Binary;
using System.Net;
using Keyhole.Core.Capture.Pcapng;
using Keyhole.Core.Capture.Recording;
using Keyhole.Core.Monitoring;

namespace Keyhole.Tests;

/// <summary>
/// The recorder's decisions, tested against scripted packets rather than a live adapter.
///
/// What matters here is the scoping: a capture that records more than the target's traffic
/// writes a bystander's conversations into a file that also holds TLS keys, and one that
/// records less is quietly incomplete. Neither failure is visible by looking at the file.
/// </summary>
public class PacketRecordingTests
{
    [Fact]
    public void Only_the_targets_packets_are_recorded()
    {
        using var world = new RecordingHarness(targetPorts: [51000]);

        world.Deliver(sourcePort: 51000, destinationPort: 443);   // the target, outbound
        world.Deliver(sourcePort: 443, destinationPort: 51000);   // the target, inbound
        world.Deliver(sourcePort: 52000, destinationPort: 443);   // somebody else
        world.Deliver(sourcePort: 443, destinationPort: 52000);   // somebody else

        var summary = world.Stop();

        Assert.Equal(2, summary.Packets);

        // The discarded majority is the evidence that scoping happened at all: without it
        // the counts would be equal and the test would pass for the wrong reason.
        Assert.Equal(4, summary.PacketsConsidered);
    }

    [Fact]
    public void Both_directions_of_a_connection_are_kept()
    {
        // A captured packet carries no direction, so the local port is the source on the
        // way out and the destination on the way in. Testing one direction only would miss
        // half of every conversation.
        using var world = new RecordingHarness(targetPorts: [51000]);

        world.Deliver(sourcePort: 51000, destinationPort: 443);
        world.Deliver(sourcePort: 443, destinationPort: 51000);

        Assert.Equal(2, world.Stop().Packets);
    }

    [Fact]
    public void Packets_keep_arriving_for_a_port_that_has_closed()
    {
        using var world = new RecordingHarness(targetPorts: [51000]);

        world.Deliver(sourcePort: 51000, destinationPort: 443);

        // The socket is gone from the table, but its last packets are still in flight.
        // A FIN or RST arriving now is the end of the target's own conversation, and
        // dropping it would truncate every TLS session's closure.
        world.SetPorts([]);
        world.Deliver(sourcePort: 443, destinationPort: 51000);

        Assert.Equal(2, world.Stop().Packets);
    }

    [Fact]
    public void A_port_opened_mid_session_is_picked_up()
    {
        using var world = new RecordingHarness(targetPorts: [51000]);

        world.Deliver(sourcePort: 51000, destinationPort: 443);

        // A browser opens connections throughout a session, and its network work happens
        // in child processes that did not exist at launch. A scope fixed at the start
        // would record only the first connection.
        world.SetPorts([51000, 51001]);
        world.Deliver(sourcePort: 51001, destinationPort: 443);

        Assert.Equal(2, world.Stop().Packets);
    }

    [Fact]
    public void A_connection_opened_between_refreshes_still_gets_its_handshake()
    {
        // The defect the first real browser run exposed. 40 MB of packets were recorded
        // and exactly one request of five TLS connections came back decodable, because a
        // connection opening between two scope refreshes had its first packets dropped —
        // and the first packets of a TLS connection include the ClientHello, which carries
        // the client random that joins the connection to its key. Lose that one packet and
        // the rest is recorded perfectly and readable never.
        using var world = new RecordingHarness(targetPorts: [51000]);

        // Establish the refresh timestamp, so the periodic refresh is not due.
        world.Deliver(sourcePort: 51000, destinationPort: 443);

        // The OS knows about the new socket; the tracker does not yet, and the clock has
        // not moved, so nothing on a timer will tell it.
        world.SetPortsBetweenRefreshes([51000, 51001]);

        world.Deliver(sourcePort: 51001, destinationPort: 443, syn: true);
        world.Deliver(sourcePort: 51001, destinationPort: 443, payloadBytes: 300);

        // The SYN and the handshake that follows it, not just the later traffic.
        Assert.Equal(3, world.Stop().Packets);
    }

    [Fact]
    public void A_handshake_that_arrives_before_the_scope_knows_the_port_is_held_and_released()
    {
        // The gap that forcing a refresh on a SYN narrowed but could not close. During a
        // browser's startup burst, connections open faster than the rate-limited refresh
        // may run, so a connection's opening packets can arrive while its port is still
        // unknown. For TLS those packets carry the ClientHello, and without it the
        // connection is recorded perfectly and readable never.
        using var world = new RecordingHarness(targetPorts: [51000]);

        // Establish the refresh timestamp so nothing on a timer is due, and exhaust the
        // forced-refresh allowance so the SYN below cannot resolve itself immediately.
        world.Deliver(sourcePort: 51000, destinationPort: 443);
        world.Deliver(sourcePort: 59999, destinationPort: 443, syn: true);

        // A connection opens. The OS does not report it yet either, so even a refresh
        // would not find it — which is the situation the buffer exists for.
        world.Deliver(sourcePort: 51001, destinationPort: 443, syn: true);
        world.Deliver(sourcePort: 51001, destinationPort: 443, payloadBytes: 200);

        // Nothing has been written for it so far.
        Assert.Equal(1, world.PacketsWrittenSoFar);

        // Now the socket table catches up and a refresh runs.
        world.SetPorts([51000, 51001]);
        world.Deliver(sourcePort: 51001, destinationPort: 443, payloadBytes: 100);

        // The SYN, the held handshake and the new packet: the whole connection from its
        // first byte, not just what arrived after the scope noticed.
        Assert.Equal(4, world.Stop().Packets);
    }

    [Fact]
    public void Held_packets_for_another_application_are_never_written()
    {
        // The buffer must not become a way for a bystander's traffic to reach a file that
        // also holds TLS keys. A connection that never joins the scope is dropped.
        using var world = new RecordingHarness(targetPorts: [51000]);

        world.Deliver(sourcePort: 51000, destinationPort: 443);

        world.Deliver(sourcePort: 52000, destinationPort: 443, syn: true);
        world.Deliver(sourcePort: 52000, destinationPort: 443, payloadBytes: 400);

        // Never appears in the socket table as ours.
        world.SetPorts([51000]);
        world.Deliver(sourcePort: 51000, destinationPort: 443);

        Assert.Equal(2, world.Stop().Packets);
    }

    [Fact]
    public void Only_connection_openings_are_held()
    {
        // Without this the buffer would fill with the middle of every other application's
        // streams — a memory problem, and the wrong thing to keep in a process that writes
        // TLS keys to disk.
        using var world = new RecordingHarness(targetPorts: [51000]);

        world.Deliver(sourcePort: 51000, destinationPort: 443);

        // Mid-stream traffic for a connection no SYN was ever seen for.
        for (var i = 0; i < 50; i++)
        {
            world.Deliver(sourcePort: 53000, destinationPort: 443, payloadBytes: 500);
        }

        // Even once it becomes ours, nothing was kept, because nothing marked it as a
        // connection being opened.
        world.SetPorts([51000, 53000]);
        world.Deliver(sourcePort: 53000, destinationPort: 443, payloadBytes: 500);

        Assert.Equal(2, world.Stop().Packets);
    }

    [Fact]
    public void A_connection_that_joins_the_scope_at_the_very_end_still_gets_its_handshake()
    {
        // Stopping runs one last release pass, so a connection resolved in a session's
        // final moments is not silently truncated.
        using var world = new RecordingHarness(targetPorts: [51000]);

        world.Deliver(sourcePort: 51000, destinationPort: 443);
        world.Deliver(sourcePort: 51002, destinationPort: 443, syn: true);

        // The table catches up, but no further packet arrives to trigger a release.
        world.SetPortsBetweenRefreshes([51000, 51002]);
        world.Refresh();

        Assert.Equal(2, world.Stop().Packets);
    }

    [Fact]
    public void A_mid_stream_packet_does_not_force_a_scope_rebuild()
    {
        // The refresh is only forced for a connection being opened. Doing it for any
        // unrecognised packet would mean enumerating every socket on the machine for
        // every packet of every other application's traffic.
        using var world = new RecordingHarness(targetPorts: [51000]);

        world.Deliver(sourcePort: 51000, destinationPort: 443);

        world.SetPortsBetweenRefreshes([51000, 51001]);
        world.Deliver(sourcePort: 51001, destinationPort: 443, payloadBytes: 300);

        Assert.Equal(1, world.Stop().Packets);
    }

    [Fact]
    public void A_syn_from_another_application_is_still_not_recorded()
    {
        // Forcing a refresh must not widen the scope. The rebuild only asks the socket
        // table who owns the port; a port that belongs to someone else stays excluded.
        using var world = new RecordingHarness(targetPorts: [51000]);

        world.Deliver(sourcePort: 51000, destinationPort: 443);
        world.Deliver(sourcePort: 52000, destinationPort: 443, syn: true);

        Assert.Equal(1, world.Stop().Packets);
    }

    [Fact]
    public void Recording_stops_at_the_size_ceiling()
    {
        // Small enough that a handful of packets reaches it.
        using var world = new RecordingHarness(targetPorts: [51000], maxBytes: 4096);

        for (var i = 0; i < 200; i++)
        {
            world.Deliver(sourcePort: 51000, destinationPort: 443, payloadBytes: 500);
        }

        var summary = world.Stop();

        Assert.True(summary.CapReached);
        Assert.True(summary.Bytes <= 4096, $"The file grew to {summary.Bytes} bytes past a 4096 cap.");

        // Some packets must have made it: a ceiling that records nothing is a bug, not a
        // limit.
        Assert.True(summary.Packets > 0);

        // And the session goes on: the point of the ceiling is to stop writing, not to
        // end the capture.
        Assert.True(summary.PacketsConsidered > summary.Packets);
    }

    [Fact]
    public void A_capped_capture_is_still_a_readable_file()
    {
        using var world = new RecordingHarness(targetPorts: [51000], maxBytes: 4096);

        for (var i = 0; i < 200; i++)
            {
            world.Deliver(sourcePort: 51000, destinationPort: 443, payloadBytes: 500);
        }

        var summary = world.Stop();

        // Truncating at a packet boundary is the whole reason the cap is checked before
        // the write rather than after: a half-written block would make the file unopenable.
        Assert.NotNull(summary.PcapngPath);
        AssertWalkable(summary.PcapngPath!);
    }

    [Fact]
    public void The_keylog_ends_up_inside_the_capture()
    {
        using var world = new RecordingHarness(targetPorts: [51000]);

        world.Deliver(sourcePort: 51000, destinationPort: 443);

        const string keylog = "CLIENT_HANDSHAKE_TRAFFIC_SECRET abc def\n";
        var summary = world.Stop(keylog);

        Assert.True(summary.SecretsEmbedded);
        Assert.Null(summary.Detail);

        var types = BlockTypes(summary.PcapngPath!);
        var secrets = types.IndexOf(0x0000000Au);

        Assert.True(secrets >= 0, "The capture carries no secrets block.");
        Assert.True(secrets < types.IndexOf(0x00000006u), "Secrets must precede the packets.");
    }

    [Fact]
    public void A_session_with_no_secrets_says_so()
    {
        using var world = new RecordingHarness(targetPorts: [51000]);
        world.Deliver(sourcePort: 51000, destinationPort: 443);

        // A Schannel application writes no keylog. The capture is still valid; it just
        // cannot be decrypted, and the UI has to be able to say which.
        var summary = world.Stop(keylog: null);

        Assert.False(summary.SecretsEmbedded);
        Assert.NotNull(summary.Detail);
    }

    [Fact]
    public void An_unavailable_adapter_degrades_to_no_recording()
    {
        var tracker = new TargetPortTracker(new FakeSockets([]), new FakeTree([1]));

        var recording = PacketRecording.Start(
            new UnavailableDevices("Npcap is not installed."),
            tracker,
            Path.Combine(Path.GetTempPath(), $"keyhole-never-{Guid.NewGuid():N}.pcapng"),
            rootProcessId: 1,
            executablePath: null);

        // Capture sessions existed before packet recording did, and they still work
        // without it. A missing Npcap must read as a reason, not an exception.
        Assert.False(recording.IsRecording);
        Assert.Equal("Npcap is not installed.", recording.UnavailableReason);
        Assert.Null(recording.PcapngPath);

        var summary = recording.Stop(null);
        Assert.Equal(0, summary.Packets);
        Assert.Null(summary.PcapngPath);
    }

    [Fact]
    public void Non_ip_frames_are_ignored_rather_than_recorded()
    {
        using var world = new RecordingHarness(targetPorts: [51000]);

        // A real adapter carries ARP, STP and malformed frames. None has ports to match
        // against, and none may crash the capture.
        world.DeliverRaw([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 1, 2, 3, 4, 5, 0x08, 0x06]);
        world.DeliverRaw([1, 2, 3]);
        world.Deliver(sourcePort: 51000, destinationPort: 443);

        Assert.Equal(1, world.Stop().Packets);
    }

    [Fact]
    public void Stopping_twice_is_harmless()
    {
        using var world = new RecordingHarness(targetPorts: [51000]);
        world.Deliver(sourcePort: 51000, destinationPort: 443);

        var first = world.Stop("CLIENT_RANDOM aaa bbb\n");
        Assert.Equal(1, first.Packets);
        Assert.True(first.SecretsEmbedded);

        // Reached in practice: an explicit stop, then the application exits and stops the
        // recording too. The second pass must not rewrite the file or inject the secrets
        // a second time.
        var second = world.StopAgain();
        Assert.Equal(0, second.Packets);

        var types = AssertWalkable(first.PcapngPath!);
        Assert.Equal(1, types.Count(t => t == 0x0000000Au));
    }

    private static List<uint> AssertWalkable(string path) => BlockTypes(path);

    /// <summary>
    /// Walks a capture file the way a reader does, failing on any block whose declared
    /// length does not land exactly on the next one.
    /// </summary>
    private static List<uint> BlockTypes(string path)
    {
        var bytes = File.ReadAllBytes(path);
        var types = new List<uint>();
        var offset = 0;

        while (offset + 8 <= bytes.Length)
        {
            types.Add(BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset)));
            var length = (int)BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset + 4));

            Assert.True(length >= 12, $"Block at {offset} claims {length} bytes.");
            Assert.True(offset + length <= bytes.Length, $"Block at {offset} runs past the end.");
            offset += length;
        }

        Assert.Equal(bytes.Length, offset);
        return types;
    }
}

/// <summary>
/// A recording with a scripted adapter and a scripted socket table, so the recorder's
/// decisions can be driven packet by packet.
/// </summary>
internal sealed class RecordingHarness : IDisposable
{
    private readonly FakeDevice _device = new();
    private readonly FakeSockets _sockets;
    private readonly TargetPortTracker _tracker;
    private readonly PacketRecording _recording;
    private readonly string _path;
    private RecordingSummary? _summary;

    public RecordingHarness(int[] targetPorts, long maxBytes = PacketRecording.DefaultMaxBytes)
    {
        _sockets = new FakeSockets(targetPorts);
        _path = Path.Combine(Path.GetTempPath(), $"keyhole-rec-{Guid.NewGuid():N}.pcapng");

        _tracker = new TargetPortTracker(_sockets, new FakeTree([TargetPid]));

        _recording = PacketRecording.Start(
            new SingleDeviceFactory(_device),
            _tracker,
            _path,
            TargetPid,
            executablePath: null,
            maxBytes);
    }

    private const int TargetPid = 4242;

    /// <summary>
    /// Changes which ports the socket table reports for the target.
    ///
    /// The tracker refreshes on a timer, so the clock is pushed forward far enough to make
    /// the next packet trigger a rebuild — otherwise a test would have to sleep a second.
    /// </summary>
    public void SetPorts(int[] ports)
    {
        _sockets.Ports = ports;
        _clock += TargetPortTracker.RefreshInterval + TimeSpan.FromMilliseconds(1);
    }

    /// <summary>
    /// Changes the socket table without advancing the clock, so the periodic refresh
    /// cannot pick the change up.
    ///
    /// This is the real situation a browser creates: a connection opens between two
    /// refreshes, and whether its handshake is recorded depends entirely on something
    /// other than the timer noticing.
    /// </summary>
    public void SetPortsBetweenRefreshes(int[] ports) => _sockets.Ports = ports;

    /// <summary>Moves the clock on without touching the socket table.</summary>
    public void AdvancePastRefresh() =>
        _clock += TargetPortTracker.RefreshInterval + TimeSpan.FromMilliseconds(1);

    /// <summary>
    /// Rebuilds the scope directly, with no packet to trigger it. Stands in for the case
    /// where a connection resolves but no further traffic arrives to notice.
    /// </summary>
    public void Refresh() => _tracker.Refresh(TargetPid, null);

    /// <summary>Packets in the file so far, without ending the recording.</summary>
    public long PacketsWrittenSoFar => _recording.PacketsWritten;

    private TimeSpan _clock = TimeSpan.Zero;

    public void Deliver(int sourcePort, int destinationPort, int payloadBytes = 0, bool syn = false) =>
        DeliverRaw(TcpFrame(sourcePort, destinationPort, payloadBytes, syn));

    public void DeliverRaw(byte[] frame) =>
        _device.Deliver(new CapturedPacket(
            new DateTimeOffset(2026, 11, 1, 12, 0, 0, TimeSpan.Zero) + _clock,
            frame,
            frame.Length));

    public RecordingSummary Stop(string? keylog = null) => _summary ??= _recording.Stop(keylog);

    /// <summary>Stops a second time, which is what an already-stopped recording must tolerate.</summary>
    public RecordingSummary StopAgain() => _recording.Stop(null);

    public void Dispose()
    {
        _recording.Dispose();

        try
        {
            File.Delete(_path);
        }
        catch (IOException)
        {
            // A leftover temp file is not worth failing a test over.
        }
    }

    /// <summary>An Ethernet frame carrying an IPv4 TCP segment between the given ports.</summary>
    private static byte[] TcpFrame(int sourcePort, int destinationPort, int payloadBytes, bool syn = false)
    {
        var frame = new byte[14 + 20 + 20 + payloadBytes];
        var span = frame.AsSpan();

        BinaryPrimitives.WriteUInt16BigEndian(span[12..], 0x0800);   // IPv4 follows

        var ip = span[14..];
        ip[0] = 0x45;                                                 // IPv4, 20-byte header
        BinaryPrimitives.WriteUInt16BigEndian(ip[2..], (ushort)(40 + payloadBytes));
        ip[8] = 64;                                                   // TTL
        ip[9] = 6;                                                    // TCP
        new byte[] { 10, 0, 0, 5 }.CopyTo(ip[12..]);
        new byte[] { 93, 184, 216, 34 }.CopyTo(ip[16..]);

        var tcp = ip[20..];
        BinaryPrimitives.WriteUInt16BigEndian(tcp, (ushort)sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(tcp[2..], (ushort)destinationPort);
        BinaryPrimitives.WriteUInt32BigEndian(tcp[4..], 1);
        tcp[12] = 0x50;                                               // 20-byte header

        // A connection-opening SYN carries no ACK; a data segment carries PSH and ACK.
        tcp[13] = syn ? (byte)0x02 : (byte)0x18;

        return frame;
    }
}

internal sealed class FakeDevice : IPacketDevice
{
    private Action<CapturedPacket>? _onPacket;

    public string Name => "fake0";

    public string Description => "Scripted adapter";

    public PcapngLinkType LinkType => PcapngLinkType.Ethernet;

    public void StartCapture(Action<CapturedPacket> onPacket) => _onPacket = onPacket;

    public void StopCapture() => _onPacket = null;

    public void Deliver(CapturedPacket packet) => _onPacket?.Invoke(packet);

    public void Dispose() => StopCapture();
}

internal sealed class SingleDeviceFactory(IPacketDevice device) : IPacketDeviceFactory
{
    public PacketDeviceSet OpenAll(int snapLength) => new([device], null);
}

internal sealed class UnavailableDevices(string reason) : IPacketDeviceFactory
{
    public PacketDeviceSet OpenAll(int snapLength) => PacketDeviceSet.Unavailable(reason);
}

/// <summary>A socket table reporting the target's ports, changeable mid-test.</summary>
internal sealed class FakeSockets(int[] ports) : ISocketTableReader
{
    public int[] Ports { get; set; } = ports;

    public IReadOnlyList<NetworkConnection> ReadAll() =>
    [
        .. Ports.Select(port => new NetworkConnection
        {
            ProcessId = 4242,
            Protocol = TransportProtocol.Tcp,
            LocalAddress = IPAddress.Parse("10.0.0.5"),
            LocalPort = port,
            RemoteAddress = IPAddress.Parse("93.184.216.34"),
            RemotePort = 443,
            State = TcpConnectionState.Established,
        }),
    ];
}

internal sealed class FakeTree(int[] pids) : IProcessTreeReader
{
    public HashSet<int> DescendantsOf(int rootProcessId, string? executablePath) => [.. pids];
}
