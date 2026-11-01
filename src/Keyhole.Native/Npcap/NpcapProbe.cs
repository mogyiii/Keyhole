using Keyhole.Core.Capture;
using Keyhole.Native.Interop;
using Microsoft.Win32;

namespace Keyhole.Native.Npcap;

/// <summary>
/// Finds out whether this machine can capture packets.
///
/// Npcap is the one dependency Keyhole does not ship, so a missing install is a normal
/// state rather than an error — the keylog half of a capture session works without it.
/// The probe therefore has to produce an explanation, not just a verdict: "install it",
/// "start the driver" and "the library is not where this process can load it" are three
/// different problems with three different fixes.
///
/// Every lookup is defensive. A machine with a half-removed Npcap, a locked-down registry
/// or no service control access must still get a sentence back, because the alternative is
/// the Capture tab throwing on open.
/// </summary>
public sealed class NpcapProbe
{
    /// <summary>The driver service Npcap installs. Runs at boot as a kernel service.</summary>
    public const string ServiceName = "npcap";

    /// <summary>
    /// Where Npcap keeps its own copy of the library. Always present.
    /// </summary>
    private static string NpcapSystemDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.System), "Npcap");

    /// <summary>
    /// Where Npcap puts a WinPcap-compatible shim, but only if that box was ticked during
    /// installation. Its absence is not a problem as long as the directory above is found.
    /// </summary>
    private static string WinPcapCompatLibrary => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.System), "wpcap.dll");

    public NpcapStatus Detect()
    {
        var registry = ReadRegistry();
        var library = FindLibrary();

        if (library is null && registry.InstallDirectory is null)
        {
            return new NpcapStatus(
                NpcapState.Missing,
                null,
                null,
                false,
                "Npcap is not installed, so Keyhole cannot record packets. TLS key logging " +
                "works without it.");
        }

        // Installed but the library is unreachable. Rare, and worth distinguishing from a
        // missing install: reinstalling is the fix, not installing.
        if (library is null)
        {
            return new NpcapStatus(
                NpcapState.Unusable,
                registry.Version,
                registry.InstallDirectory,
                registry.AdminOnly,
                $"Npcap {registry.Version ?? "is"} registered at {registry.InstallDirectory}, but " +
                "wpcap.dll was not found in System32. Reinstalling Npcap should restore it.");
        }

        var serviceState = ReadServiceState();

        if (serviceState == ServiceApi.SERVICE_RUNNING)
        {
            return new NpcapStatus(
                NpcapState.Ready,
                registry.Version,
                registry.InstallDirectory,
                registry.AdminOnly,
                registry.Version is { } version
                    ? $"Npcap {version} is running."
                    : "Npcap is running.");
        }

        // The files are there but the driver is not. Treat it as stopped rather than
        // ready: opening a device would fail, and "start the driver" is closer to the
        // truth than "install Npcap".
        return new NpcapStatus(
            NpcapState.Stopped,
            registry.Version,
            registry.InstallDirectory,
            registry.AdminOnly,
            serviceState is { } state
                ? $"The Npcap driver is installed but {DescribeState(state)}. " +
                  "Start the 'npcap' service to record packets."
                : "Npcap is installed but its driver service could not be queried. " +
                  "Packet recording will not start.");
    }

    private static string DescribeState(uint state) => state switch
    {
        ServiceApi.SERVICE_STOPPED => "stopped",
        ServiceApi.SERVICE_START_PENDING => "still starting",
        ServiceApi.SERVICE_STOP_PENDING => "stopping",
        _ => "not running",
    };

    /// <summary>
    /// The library SharpPcap needs, or null when neither location has it.
    /// Prefers Npcap's own directory: the System32 copy is a compatibility shim that only
    /// exists when the installer was told to provide it.
    /// </summary>
    public static string? FindLibrary()
    {
        var own = Path.Combine(NpcapSystemDirectory, "wpcap.dll");

        try
        {
            if (File.Exists(own))
            {
                return own;
            }

            return File.Exists(WinPcapCompatLibrary) ? WinPcapCompatLibrary : null;
        }
        catch (IOException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>
    /// The driver service's current state, or null when it cannot be queried at all.
    ///
    /// Asks for query rights only. The UI half of Keyhole runs unelevated and still needs
    /// to explain why capture is unavailable, and requesting control access would fail
    /// there for no benefit.
    /// </summary>
    private static uint? ReadServiceState()
    {
        var manager = ServiceApi.OpenSCManager(null, null, ServiceApi.SC_MANAGER_CONNECT);
        if (manager == IntPtr.Zero)
        {
            return null;
        }

        var service = IntPtr.Zero;
        try
        {
            service = ServiceApi.OpenService(manager, ServiceName, ServiceApi.SERVICE_QUERY_STATUS);
            if (service == IntPtr.Zero)
            {
                // No such service, or no permission to ask. Either way there is nothing to
                // report but the absence, which the caller already handles.
                return null;
            }

            return ServiceApi.QueryServiceStatus(service, out var status)
                ? status.dwCurrentState
                : null;
        }
        finally
        {
            if (service != IntPtr.Zero)
            {
                ServiceApi.CloseServiceHandle(service);
            }

            ServiceApi.CloseServiceHandle(manager);
        }
    }

    /// <summary>
    /// Reads what Npcap records about itself.
    ///
    /// Two keys are involved and neither is guaranteed: the install settings live under a
    /// WOW6432Node path (the installer is 32-bit), while the version only appears in the
    /// uninstall entry. Both are read opportunistically — the version is for display, so
    /// missing it must not change the verdict.
    /// </summary>
    private static RegistryFacts ReadRegistry()
    {
        string? installDirectory = null;
        var adminOnly = false;

        foreach (var path in (string[])[@"SOFTWARE\WOW6432Node\Npcap", @"SOFTWARE\Npcap"])
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(path);
                if (key is null)
                {
                    continue;
                }

                installDirectory ??= key.GetValue(null) as string;

                // Npcap can be installed so that only administrators may capture. Keyhole
                // runs as LocalSystem so it is unaffected, but it explains why an
                // unelevated tool on the same machine sees no adapters.
                if (key.GetValue("AdminOnly") is int flag && flag != 0)
                {
                    adminOnly = true;
                }
            }
            catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException)
            {
                // A locked-down registry is not a reason to report Npcap missing: the
                // file and service checks still decide.
            }
        }

        return new RegistryFacts(ReadVersion(), installDirectory, adminOnly);
    }

    private static string? ReadVersion()
    {
        string[] uninstallKeys =
        [
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst",
        ];

        foreach (var path in uninstallKeys)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(path);
                if (key?.GetValue("DisplayVersion") is string version && version.Length > 0)
                {
                    return version;
                }
            }
            catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException)
            {
                // Display only; the verdict does not depend on it.
            }
        }

        return null;
    }

    private readonly record struct RegistryFacts(
        string? Version,
        string? InstallDirectory,
        bool AdminOnly);
}
