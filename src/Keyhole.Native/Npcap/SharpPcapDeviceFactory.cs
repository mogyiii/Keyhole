using Keyhole.Core.Capture;
using Keyhole.Core.Ipc;
using Keyhole.Core.Capture.Pcapng;
using Keyhole.Core.Capture.Recording;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace Keyhole.Native.Npcap;

/// <summary>
/// Opens Npcap adapters through SharpPcap.
///
/// Every adapter is opened, not one chosen by heuristic. Which adapter carries a given
/// connection is not knowable in advance — a laptop switching between Wi-Fi and Ethernet,
/// a VPN appearing mid-session, loopback traffic on its own pseudo-adapter — and picking
/// the "main" one would silently miss whatever went elsewhere. Scoping to the application
/// happens per packet instead, where it can be done correctly.
///
/// Adapters that refuse to open are skipped individually: a machine typically has several
/// virtual adapters that are disconnected or need rights Keyhole has not got, and none of
/// them should stop the real one from being captured.
/// </summary>
public sealed class SharpPcapDeviceFactory(
    NpcapProbe? probe = null,
    ILogger<SharpPcapDeviceFactory>? logger = null) : IPacketDeviceFactory
{
    private readonly NpcapProbe _probe = probe ?? new NpcapProbe();
    private readonly ILogger _logger = logger ?? NullLogger<SharpPcapDeviceFactory>.Instance;

    /// <summary>
    /// How long the driver may buffer packets before handing them over.
    ///
    /// Short enough that a stopped capture does not lose its last packets, long enough
    /// that the driver is not woken for every frame on a busy link.
    /// </summary>
    private const int ReadTimeoutMilliseconds = 250;

    public PacketDeviceSet OpenAll(int snapLength)
    {
        // Asked before touching SharpPcap: loading the library when Npcap is absent
        // throws a DllNotFoundException, which says far less than the probe can.
        var status = _probe.Detect();
        if (!status.IsReady)
        {
            // Npcap's own state is already a code the interface understands, so the
            // recording issue is simply "no Npcap" and the UI says which of the four
            // states it is from the service status.
            return PacketDeviceSet.Unavailable(status.Detail, ReasonCodes.RecordingNoNpcap);
        }

        CaptureDeviceList all;
        try
        {
            all = CaptureDeviceList.Instance;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Npcap reported ready but its adapter list could not be read.");

            return PacketDeviceSet.Unavailable(
                $"Npcap is installed but its adapter list could not be read: {ex.Message}",
                ReasonCodes.RecordingNoAdapter);
        }

        var devices = new List<IPacketDevice>();
        var failures = new List<string>();

        foreach (var device in all.OfType<LibPcapLiveDevice>())
        {
            try
            {
                device.Open(new DeviceConfiguration
                {
                    Mode = DeviceModes.None,
                    ReadTimeout = ReadTimeoutMilliseconds,
                    Snaplen = snapLength,
                });

                devices.Add(new SharpPcapDevice(device, _logger));
            }
            catch (Exception ex)
            {
                // Expected for disconnected virtual adapters; logged at debug because a
                // typical machine has several and they are not a problem.
                _logger.LogDebug(ex, "Adapter {Adapter} could not be opened.", device.Name);
                failures.Add(device.Description ?? device.Name);
            }
        }

        if (devices.Count == 0)
        {
            return PacketDeviceSet.Unavailable(
                failures.Count > 0
                    ? $"Npcap is running but none of its {failures.Count} adapters could be " +
                      "opened. Recording packets needs the service to be elevated."
                    : "Npcap reported no network adapters to capture from.",
                ReasonCodes.RecordingNoAdapter);
        }

        _logger.LogInformation(
            "Opened {Opened} of {Total} adapters for capture.", devices.Count, all.Count);

        return new PacketDeviceSet(devices, null, null);
    }
}

/// <summary>One opened adapter, bridging SharpPcap's events to Keyhole's callback.</summary>
internal sealed class SharpPcapDevice(LibPcapLiveDevice device, ILogger logger) : IPacketDevice
{
    private Action<CapturedPacket>? _onPacket;
    private bool _capturing;

    public string Name => device.Name;

    public string Description => device.Description ?? device.Name;

    public PcapngLinkType LinkType => device.LinkType switch
    {
        LinkLayers.Ethernet => PcapngLinkType.Ethernet,
        LinkLayers.Null => PcapngLinkType.Null,
        LinkLayers.Raw => PcapngLinkType.Raw,

        // An unrecognised link type would be written into the file as a wrong one, and
        // every packet from the adapter would then be mis-parsed. Ethernet is the only
        // safe guess, and the adapters that matter are all Ethernet.
        _ => PcapngLinkType.Ethernet,
    };

    public void StartCapture(Action<CapturedPacket> onPacket)
    {
        _onPacket = onPacket;
        device.OnPacketArrival += OnPacketArrival;
        device.StartCapture();
        _capturing = true;
    }

    private void OnPacketArrival(object sender, PacketCapture capture)
    {
        try
        {
            var raw = capture.GetPacket();

            // The data is only valid for this callback — SharpPcap hands out a view over
            // the driver's buffer — so the handler must consume it synchronously. It does:
            // it copies the bytes it keeps into the capture file.
            _onPacket?.Invoke(new CapturedPacket(
                new DateTimeOffset(raw.Timeval.Date, TimeSpan.Zero),
                raw.Data,
                raw.PacketLength));
        }
        catch (Exception ex)
        {
            // On a driver thread: letting this escape would end the process.
            logger.LogError(ex, "Failed to handle a packet from {Adapter}.", device.Name);
        }
    }

    public void StopCapture()
    {
        if (!_capturing)
        {
            return;
        }

        _capturing = false;
        device.OnPacketArrival -= OnPacketArrival;

        try
        {
            device.StopCapture();
        }
        catch (Exception ex)
        {
            logger.LogDebug(ex, "Adapter {Adapter} did not stop cleanly.", device.Name);
        }
    }

    public void Dispose()
    {
        StopCapture();

        try
        {
            if (device.Opened)
            {
                device.Close();
            }
        }
        catch (Exception ex)
        {
            logger.LogDebug(ex, "Adapter {Adapter} did not close cleanly.", device.Name);
        }
    }
}
