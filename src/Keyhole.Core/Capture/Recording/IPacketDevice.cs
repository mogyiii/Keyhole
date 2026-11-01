using Keyhole.Core.Capture.Pcapng;

namespace Keyhole.Core.Capture.Recording;

/// <summary>
/// One network adapter Keyhole can read packets from.
///
/// An interface rather than SharpPcap's types directly, so the recorder's filtering,
/// scoping and size-cap logic can be tested against scripted packets. Those are the parts
/// with decisions in them; the parts that talk to the driver have none.
/// </summary>
public interface IPacketDevice : IDisposable
{
    /// <summary>The adapter's system name, as Npcap reports it.</summary>
    string Name { get; }

    /// <summary>Something a person can recognise, for the capture's interface description.</summary>
    string Description { get; }

    /// <summary>
    /// How this adapter frames packets. Ethernet for ordinary adapters, but Npcap's
    /// loopback adapter differs, and a reader told the wrong one mis-parses every packet.
    /// </summary>
    PcapngLinkType LinkType { get; }

    /// <summary>
    /// Begins delivering packets to <paramref name="onPacket"/> on a background thread.
    /// </summary>
    void StartCapture(Action<CapturedPacket> onPacket);

    /// <summary>Stops delivery. Safe to call when capture never started.</summary>
    void StopCapture();
}

/// <summary>One packet as it came off an adapter, before anything has looked inside it.</summary>
/// <param name="Timestamp">When the driver saw it.</param>
/// <param name="Data">
/// The captured bytes. Valid only for the duration of the callback — the capture driver
/// reuses its buffers, so anything kept must be copied.
/// </param>
/// <param name="OriginalLength">
/// Length on the wire, which exceeds <see cref="Data"/> when the snaplen truncated it.
/// </param>
public readonly record struct CapturedPacket(
    DateTimeOffset Timestamp,
    ReadOnlyMemory<byte> Data,
    int OriginalLength);

/// <summary>
/// Opens the adapters worth capturing on.
/// </summary>
public interface IPacketDeviceFactory
{
    /// <summary>
    /// Opens every usable adapter. An empty set with a reason is a normal result — Npcap
    /// may simply not be installed — and must not be reported as a failure of the capture.
    /// </summary>
    /// <param name="snapLength">Bytes to keep per packet.</param>
    PacketDeviceSet OpenAll(int snapLength);
}

/// <summary>
/// The adapters that opened, plus why there are none or fewer than expected.
/// </summary>
/// <param name="Devices">Adapters ready to capture from.</param>
/// <param name="UnavailableReason">
/// Why packet recording cannot run, or null when it can. A sentence for the user, not a
/// diagnostic: "Npcap is not installed" is actionable, an exception type is not.
/// </param>
public sealed record PacketDeviceSet(
    IReadOnlyList<IPacketDevice> Devices,
    string? UnavailableReason)
{
    public static PacketDeviceSet Unavailable(string reason) => new([], reason);
}
