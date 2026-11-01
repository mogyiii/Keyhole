namespace Keyhole.Core.Capture;

/// <summary>
/// What Keyhole found when it looked for Npcap.
///
/// Packet capture is the one Keyhole feature that depends on software we do not ship, so
/// the answer has to be richer than a bool: "not installed" and "installed but the driver
/// is stopped" need different advice, and the UI cannot give it from a yes/no.
/// </summary>
public enum NpcapState
{
    /// <summary>Driver present and running. Capture can start.</summary>
    Ready,

    /// <summary>Nothing found. The user has to install it; Keyhole can offer to fetch it.</summary>
    Missing,

    /// <summary>
    /// Installed but the driver service is not running. Usually a disabled service rather
    /// than a broken install, so the advice is "start it", not "reinstall".
    /// </summary>
    Stopped,

    /// <summary>
    /// Installed and running, but the library is not reachable from this process — a
    /// WinPcap-compatibility-mode choice at install time changes where wpcap.dll lands.
    /// </summary>
    Unusable,
}

/// <summary>
/// The result of probing for Npcap, carrying a sentence the UI can show as-is.
/// </summary>
/// <param name="State">Whether capture can start.</param>
/// <param name="Version">Installed version when the registry reports one.</param>
/// <param name="InstallDirectory">Where Npcap put itself, when known.</param>
/// <param name="AdminOnly">
/// True when Npcap was installed with "restrict to administrators". It does not stop
/// Keyhole — the service runs as LocalSystem — but it does explain why the same machine
/// cannot capture from an unelevated tool, which is a question worth pre-empting.
/// </param>
/// <param name="Detail">One sentence naming what is wrong and what to do about it.</param>
public sealed record NpcapStatus(
    NpcapState State,
    string? Version,
    string? InstallDirectory,
    bool AdminOnly,
    string Detail)
{
    public bool IsReady => State == NpcapState.Ready;

    /// <summary>Why capture is unavailable, or null when it is available.</summary>
    public string? UnavailableReason => IsReady ? null : Detail;

    /// <summary>
    /// Whether offering to download the installer makes sense. Only for a genuinely
    /// absent install: downloading a second copy would not fix a stopped driver.
    /// </summary>
    public bool CanOfferInstall => State == NpcapState.Missing;

    public static NpcapStatus Unknown(string detail) =>
        new(NpcapState.Missing, null, null, false, detail);
}
