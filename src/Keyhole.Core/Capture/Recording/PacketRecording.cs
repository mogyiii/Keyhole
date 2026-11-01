using Keyhole.Core.Capture.Pcapng;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Keyhole.Core.Capture.Recording;

/// <summary>
/// Records one capture session's packets to a pcapng file, scoped to the application being
/// captured.
///
/// Three things have to hold at once, and they pull against each other. The recording must
/// contain the target's traffic — which means reading from every adapter, since which one
/// carries a connection is not known in advance. It must contain <em>only</em> the
/// target's traffic, because the file ends up alongside TLS keys and recording a
/// bystander's conversations into it would be a privacy failure, not an inconvenience.
/// And it must not fill the disk: a browser session produces hundreds of megabytes in
/// minutes.
///
/// So: open everything, decide per packet, and stop writing at a ceiling while leaving the
/// session itself running. Hitting the ceiling is reported rather than silent — a capture
/// that quietly stopped recording half an hour ago is worse than no capture.
/// </summary>
public sealed class PacketRecording : IDisposable
{
    private readonly List<IPacketDevice> _devices;

    /// <summary>
    /// Per adapter: the interface id its packets must carry, and how it frames them.
    /// Looked up for every packet, so it is a dictionary rather than a scan of the
    /// adapter list.
    /// </summary>
    private readonly Dictionary<string, AdapterBinding> _adapters = [];
    private readonly PcapngWriter? _writer;
    private readonly TargetPortTracker _scope;
    private readonly string _pcapngPath;
    private readonly int _rootProcessId;
    private readonly string? _executablePath;
    private readonly long _maxBytes;
    private readonly ILogger _logger;
    private readonly Lock _gate = new();

    private bool _capReached;
    private bool _stopped;
    private long _packetsConsidered;

    /// <summary>
    /// Bytes kept per packet.
    ///
    /// The full frame, not a prefix: a truncated packet cannot be decrypted, and decoding
    /// what the application actually sent is the point of the milestone. Capping the file
    /// size is the right lever for disk use, because it bounds the total rather than
    /// damaging every packet.
    /// </summary>
    public const int SnapLength = 65535;

    /// <summary>The ceiling a session's pcap may reach before recording stops.</summary>
    public const long DefaultMaxBytes = 512L * 1024 * 1024;

    /// <summary>
    /// An enhanced packet block's own bytes: the 12-byte frame, five header fields and up
    /// to three bytes of padding. Used to project a write's size before making it.
    /// </summary>
    private const int PacketBlockOverhead = 12 + 20 + 3;

    private readonly record struct AdapterBinding(int Id, PcapngLinkType LinkType);

    /// <summary>
    /// How long a connection's opening packets are held while waiting to find out whether
    /// the connection is the target's.
    ///
    /// A TLS handshake completes in well under a second, so two is generous. The window
    /// only has to outlast the gap between a connection appearing and the scope noticing.
    /// </summary>
    private static readonly TimeSpan HoldWindow = TimeSpan.FromSeconds(2);

    /// <summary>
    /// A ceiling on held packets, across all connections.
    ///
    /// Small on purpose: only connection openings are ever held, never established
    /// traffic, so this is the beginnings of a few thousand connections rather than
    /// seconds of a link's full throughput.
    /// </summary>
    private const long MaxHeldBytes = 8L * 1024 * 1024;

    /// <summary>
    /// Packets held per connection. A TLS ClientHello arrives within the first handful, so
    /// a connection that has sent this many without joining the scope is not the target's.
    /// </summary>
    private const int MaxHeldPerConnection = 32;

    /// <summary>
    /// Opening packets of connections that do not match the scope <em>yet</em>.
    ///
    /// This is what closes the gap the live runs exposed. A connection's first packets
    /// arrive before the scope can know its port, and for TLS those packets include the
    /// ClientHello — the one thing that ties the connection to its key. Dropping it leaves
    /// a perfectly recorded conversation that nothing will ever read.
    ///
    /// Forcing a scope refresh on a SYN narrowed the gap but could not close it: during a
    /// browser's startup burst, connections open faster than the refresh may run. Holding
    /// the packets instead does not race at all — when a port turns out to be the
    /// target's, its opening packets are written then.
    ///
    /// Only openings are held, and only for connections that showed a SYN. That keeps this
    /// from becoming a rolling buffer of every application's traffic, which would be both
    /// a memory problem and the wrong thing to keep in a process that writes TLS keys to
    /// disk.
    /// </summary>
    private readonly Dictionary<PortPair, List<HeldPacket>> _held = [];

    private long _heldBytes;

    /// <summary>A packet kept in case its connection turns out to belong to the target.</summary>
    private readonly record struct HeldPacket(
        int InterfaceId,
        DateTimeOffset Timestamp,
        byte[] Data,
        int OriginalLength);

    /// <summary>
    /// A connection's two ports in a fixed order, so both directions map to one entry.
    /// </summary>
    private readonly record struct PortPair(int Low, int High)
    {
        public static PortPair For(int a, int b) => a <= b ? new(a, b) : new(b, a);
    }

    private PacketRecording(
        List<IPacketDevice> devices,
        PcapngWriter? writer,
        TargetPortTracker scope,
        string pcapngPath,
        int rootProcessId,
        string? executablePath,
        long maxBytes,
        string? unavailableReason,
        ILogger logger)
    {
        _devices = devices;
        _writer = writer;
        _scope = scope;
        _pcapngPath = pcapngPath;
        _rootProcessId = rootProcessId;
        _executablePath = executablePath;
        _maxBytes = maxBytes;
        _logger = logger;
        UnavailableReason = unavailableReason;
    }

    /// <summary>Why no packets are being recorded, or null when recording is live.</summary>
    public string? UnavailableReason { get; }

    public bool IsRecording => _writer is not null && !_stopped && !_capReached;

    /// <summary>Where the capture file is, or null when nothing is being recorded.</summary>
    public string? PcapngPath => _writer is null ? null : _pcapngPath;

    /// <summary>Packets written so far, without ending the recording.</summary>
    public long PacketsWritten
    {
        get
        {
            lock (_gate)
            {
                return _writer?.PacketsWritten ?? 0;
            }
        }
    }

    /// <summary>
    /// Begins recording. Never throws for an unavailable capture backend: a session whose
    /// packets cannot be recorded still logs TLS keys, which is what M5 delivered, so the
    /// absence is reported and the session goes on.
    /// </summary>
    public static PacketRecording Start(
        IPacketDeviceFactory factory,
        TargetPortTracker scope,
        string pcapngPath,
        int rootProcessId,
        string? executablePath,
        long maxBytes = DefaultMaxBytes,
        ILogger<PacketRecording>? logger = null)
    {
        var log = (ILogger?)logger ?? NullLogger<PacketRecording>.Instance;

        PacketDeviceSet set;
        try
        {
            set = factory.OpenAll(SnapLength);
        }
        catch (Exception ex)
        {
            log.LogWarning(ex, "Could not open any capture adapter.");
            set = PacketDeviceSet.Unavailable($"No capture adapter could be opened: {ex.Message}");
        }

        if (set.Devices.Count == 0)
        {
            return new PacketRecording(
                [], null, scope, pcapngPath, rootProcessId, executablePath, maxBytes,
                set.UnavailableReason ?? "No capture adapter was available.", log);
        }

        PcapngWriter writer;
        try
        {
            writer = PcapngWriter.Create(pcapngPath);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            foreach (var device in set.Devices)
            {
                device.Dispose();
            }

            log.LogWarning(ex, "Could not create the capture file {Path}.", pcapngPath);

            return new PacketRecording(
                [], null, scope, pcapngPath, rootProcessId, executablePath, maxBytes,
                $"The capture file could not be created: {ex.Message}", log);
        }

        var recording = new PacketRecording(
            [.. set.Devices], writer, scope, pcapngPath, rootProcessId, executablePath,
            maxBytes, set.UnavailableReason, log);

        recording.Begin();
        return recording;
    }

    private void Begin()
    {
        // Seed the scope before the first packet arrives. Without this the connections the
        // application already had open would not be recognised until the first refresh.
        _scope.Refresh(_rootProcessId, _executablePath);

        foreach (var device in _devices)
        {
            // One interface block per adapter, keyed by name so each packet can be
            // attributed to the adapter it came from with the right link type.
            var id = _writer!.AddInterface(device.LinkType, device.Description, SnapLength);
            _adapters[device.Name] = new AdapterBinding(id, device.LinkType);
        }

        foreach (var device in _devices)
        {
            var name = device.Name;

            try
            {
                device.StartCapture(packet => OnPacket(name, packet));
            }
            catch (Exception ex)
            {
                // One adapter refusing to capture is common — a disconnected virtual
                // adapter, for instance — and must not take the others down with it.
                _logger.LogWarning(ex, "Adapter {Adapter} could not start capturing.", name);
            }
        }

        _logger.LogInformation(
            "Recording packets for pid {Pid} on {Adapters} adapter(s) to {Path}, cap {Cap} bytes.",
            _rootProcessId, _devices.Count, _pcapngPath, _maxBytes);
    }

    /// <summary>
    /// Decides on one packet. Called on each adapter's capture thread.
    /// </summary>
    private void OnPacket(string adapterName, CapturedPacket packet)
    {
        try
        {
            Interlocked.Increment(ref _packetsConsidered);

            if (_scope.RefreshIfStale(_rootProcessId, _executablePath, packet.Timestamp))
            {
                ReleaseHeldPackets(packet.Timestamp);
            }

            if (!_adapters.TryGetValue(adapterName, out var adapter))
            {
                return;
            }

            if (TransportSegment.TryRead(packet.Data, adapter.LinkType) is not { } segment)
            {
                return;
            }

            if (!_scope.Owns(segment.Source.Port, segment.Destination.Port))
            {
                HoldIfOpeningAConnection(adapter.Id, segment, packet);
                return;
            }

            lock (_gate)
            {
                if (_stopped || _capReached || _writer is null)
                {
                    return;
                }

                // Checked against the projected size, not the current one, so the ceiling
                // is a limit the file respects rather than one it overshoots by a packet.
                var projected = _writer.BytesWritten + packet.Data.Length + PacketBlockOverhead;

                if (projected > _maxBytes)
                {
                    _capReached = true;

                    _logger.LogWarning(
                        "Capture {Path} reached its {Cap} byte ceiling after {Packets} packets; " +
                        "recording stopped, the session continues.",
                        _pcapngPath, _maxBytes, _writer.PacketsWritten);

                    return;
                }

                _writer.WritePacket(
                    adapter.Id, packet.Timestamp, packet.Data.Span, packet.OriginalLength);
            }
        }
        catch (Exception ex)
        {
            // Raised on a driver callback thread; an exception escaping here would take
            // the whole service down over a single packet.
            _logger.LogError(ex, "Failed to record a packet from {Adapter}.", adapterName);
        }
    }

    /// <summary>
    /// Keeps a packet that does not match the scope, when it might be the beginning of a
    /// connection that will.
    ///
    /// A SYN starts a candidate and triggers an immediate scope refresh — the socket
    /// exists in the OS table by the time its SYN goes out, so most connections are
    /// resolved on the spot. Anything that follows is only held if its connection is
    /// already a candidate, which is what keeps this from buffering unrelated traffic.
    /// </summary>
    private void HoldIfOpeningAConnection(
        int interfaceId, TransportSegment segment, CapturedPacket packet)
    {
        if (segment.Protocol != ProtocolType.Tcp)
        {
            // UDP has no connection opening to recognise, so there is no bounded set of
            // packets worth holding. QUIC is undecodable anyway.
            return;
        }

        var pair = PortPair.For(segment.Source.Port, segment.Destination.Port);

        lock (_gate)
        {
            if (_stopped || _writer is null)
            {
                return;
            }

            if (!_held.TryGetValue(pair, out var packets))
            {
                // Only a connection being opened may start a candidate. Without this the
                // buffer would fill with the middle of every other application's streams.
                if (!segment.IsSyn)
                {
                    return;
                }

                packets = [];
                _held[pair] = packets;
            }

            if (packets.Count < MaxHeldPerConnection && _heldBytes < MaxHeldBytes)
            {
                // Copied because the driver reuses its buffers the moment this returns.
                var copy = packet.Data.ToArray();

                packets.Add(new HeldPacket(
                    interfaceId, packet.Timestamp, copy, packet.OriginalLength));

                _heldBytes += copy.Length;
            }
        }

        // Outside the lock: a refresh enumerates sockets and processes, and holding the
        // writer lock across it would stall every other adapter's capture thread.
        if (segment.IsSyn &&
            _scope.RefreshForNewConnection(_rootProcessId, _executablePath, packet.Timestamp))
        {
            ReleaseHeldPackets(packet.Timestamp);
        }
    }

    /// <summary>
    /// Writes out held packets whose connection has turned out to be the target's, and
    /// discards the rest once their window has passed.
    ///
    /// Released packets land in the file after packets captured later, so a capture's
    /// timestamps are not strictly ascending. That is deliberate and harmless: TCP streams
    /// reassemble by sequence number, not by arrival, in Keyhole's decoder and in
    /// Wireshark alike. Buffering everything in order instead would mean delaying the
    /// whole recording to avoid a cosmetic problem.
    /// </summary>
    /// <param name="afterStop">
    /// Set for the final pass, which runs once the adapters are closed but before the file
    /// is. The ordinary guard against writing to a stopped recording has to be bypassed
    /// there, or a connection that joined the scope moments before the session ended would
    /// lose its handshake.
    /// </param>
    private void ReleaseHeldPackets(DateTimeOffset now, bool afterStop = false)
    {
        lock (_gate)
        {
            if (_held.Count == 0 || _writer is null || (_stopped && !afterStop))
            {
                return;
            }

            List<PortPair>? finished = null;

            foreach (var (pair, packets) in _held)
            {
                if (_scope.Owns(pair.Low, pair.High))
                {
                    foreach (var held in packets)
                    {
                        if (_capReached)
                        {
                            break;
                        }

                        var projected = _writer.BytesWritten + held.Data.Length + PacketBlockOverhead;
                        if (projected > _maxBytes)
                        {
                            _capReached = true;
                            break;
                        }

                        _writer.WritePacket(
                            held.InterfaceId, held.Timestamp, held.Data, held.OriginalLength);
                    }

                    (finished ??= []).Add(pair);
                    continue;
                }

                // Not ours, and old enough that it never will be.
                if (packets.Count > 0 && now - packets[0].Timestamp > HoldWindow)
                {
                    (finished ??= []).Add(pair);
                }
            }

            if (finished is null)
            {
                return;
            }

            foreach (var pair in finished)
            {
                if (_held.Remove(pair, out var packets))
                {
                    _heldBytes -= packets.Sum(p => p.Data.Length);
                }
            }
        }
    }

    /// <summary>
    /// Stops recording and finishes the file.
    /// </summary>
    /// <param name="keylogContents">
    /// The session's TLS secrets, which are written into the capture so it decrypts on its
    /// own. Null or empty when the application wrote none.
    /// </param>
    public RecordingSummary Stop(string? keylogContents)
    {
        lock (_gate)
        {
            if (_stopped)
            {
                return NothingRecorded();
            }

            _stopped = true;
        }

        foreach (var device in _devices)
        {
            try
            {
                device.StopCapture();
                device.Dispose();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Adapter {Adapter} did not stop cleanly.", device.Name);
            }
        }

        // One last pass now that no more packets can arrive: a connection that joined the
        // scope in the session's final moments still has its opening packets held, and
        // they are the ones its handshake is in.
        ReleaseHeldPackets(DateTimeOffset.UtcNow, afterStop: true);

        long packets;
        long bytes;

        lock (_gate)
        {
            packets = _writer?.PacketsWritten ?? 0;
            bytes = _writer?.BytesWritten ?? 0;

            // Whatever is left belonged to someone else. Dropped rather than written.
            _held.Clear();
            _heldBytes = 0;

            _writer?.Dispose();
        }

        if (_writer is null)
        {
            return NothingRecorded();
        }

        // The secrets go in only now, because only now do they all exist — and they go in
        // ahead of the packets, which is where a reader needs them.
        var injection = string.IsNullOrWhiteSpace(keylogContents)
            ? InjectionResult.NothingToDo("The application wrote no TLS secrets.")
            : PcapngSecretsInjector.Inject(_pcapngPath, keylogContents!);

        _logger.LogInformation(
            "Capture {Path} finished: {Packets} packets, {Bytes} bytes, secrets embedded: {Embedded}.",
            _pcapngPath, packets, bytes, injection.Succeeded);

        return new RecordingSummary(
            _pcapngPath, packets, bytes, _capReached, injection.Succeeded, injection.Detail,
            Interlocked.Read(ref _packetsConsidered));
    }

    /// <summary>
    /// The summary for a session that recorded nothing — either because no adapter was
    /// available, or because it has already been stopped once.
    /// </summary>
    private RecordingSummary NothingRecorded() => new(
        PcapngPath, 0, 0, _capReached, false, UnavailableReason,
        Interlocked.Read(ref _packetsConsidered));

    public void Dispose() => Stop(null);
}

/// <summary>What a finished recording produced.</summary>
/// <param name="PcapngPath">The capture file, or null when nothing was recorded.</param>
/// <param name="Packets">Packets written, after scoping.</param>
/// <param name="Bytes">Size of the capture file.</param>
/// <param name="CapReached">
/// Whether recording stopped early at its ceiling. The capture is then a prefix of the
/// session, which changes what conclusions can be drawn from it.
/// </param>
/// <param name="SecretsEmbedded">
/// Whether the TLS secrets are inside the capture file. When true it opens decrypted with
/// nothing configured; when false the keylog beside it still has them.
/// </param>
/// <param name="Detail">A sentence for the user when something is worth saying.</param>
/// <param name="PacketsConsidered">
/// Packets seen across all adapters before scoping. Compared against
/// <paramref name="Packets"/> it shows how much of the machine's traffic was discarded,
/// which is the evidence that scoping works.
/// </param>
public sealed record RecordingSummary(
    string? PcapngPath,
    long Packets,
    long Bytes,
    bool CapReached,
    bool SecretsEmbedded,
    string? Detail,
    long PacketsConsidered);
