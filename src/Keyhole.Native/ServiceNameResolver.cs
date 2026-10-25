using System.Runtime.InteropServices;
using Keyhole.Native.Interop;

namespace Keyhole.Native;

/// <summary>
/// Maps PIDs to the Windows services hosted inside them.
/// Without this, a large share of a machine's traffic reads as "svchost.exe" and the user
/// learns nothing: the interesting fact is that it is Windows Update or the Time service.
/// </summary>
public sealed class ServiceNameResolver
{
    private Dictionary<int, List<string>> _byProcessId = [];
    private DateTime _refreshedUtc = DateTime.MinValue;
    private readonly Lock _gate = new();

    /// <summary>
    /// How long a service map stays usable. Services start and stop rarely compared to the
    /// sampling loop, so re-enumerating every pass would be pure waste.
    /// </summary>
    private static readonly TimeSpan CacheLifetime = TimeSpan.FromSeconds(30);

    /// <summary>Service names hosted by this PID; empty for ordinary programs.</summary>
    public IReadOnlyList<string> GetServices(int processId)
    {
        lock (_gate)
        {
            if (DateTime.UtcNow - _refreshedUtc > CacheLifetime)
            {
                _byProcessId = Enumerate();
                _refreshedUtc = DateTime.UtcNow;
            }

            return _byProcessId.TryGetValue(processId, out var names) ? names : [];
        }
    }

    private static Dictionary<int, List<string>> Enumerate()
    {
        var map = new Dictionary<int, List<string>>();

        var manager = ServiceApi.OpenSCManager(
            null, null, ServiceApi.SC_MANAGER_CONNECT | ServiceApi.SC_MANAGER_ENUMERATE_SERVICE);

        if (manager == IntPtr.Zero)
        {
            // Enumeration needs no elevation, but if it is denied the monitor still works;
            // svchost connections simply stay unlabelled.
            return map;
        }

        try
        {
            uint resume = 0;

            // First call reports the buffer size it needs.
            ServiceApi.EnumServicesStatusEx(
                manager, ServiceApi.SC_ENUM_PROCESS_INFO, ServiceApi.SERVICE_WIN32,
                ServiceApi.SERVICE_STATE_ALL, IntPtr.Zero, 0,
                out var needed, out _, ref resume, null);

            if (needed == 0)
            {
                return map;
            }

            var buffer = Marshal.AllocHGlobal((int)needed);
            try
            {
                resume = 0;
                var ok = ServiceApi.EnumServicesStatusEx(
                    manager, ServiceApi.SC_ENUM_PROCESS_INFO, ServiceApi.SERVICE_WIN32,
                    ServiceApi.SERVICE_STATE_ALL, buffer, needed,
                    out _, out var returned, ref resume, null);

                if (!ok)
                {
                    return map;
                }

                var entrySize = Marshal.SizeOf<ServiceApi.ENUM_SERVICE_STATUS_PROCESS>();
                for (var i = 0; i < returned; i++)
                {
                    var entry = Marshal.PtrToStructure<ServiceApi.ENUM_SERVICE_STATUS_PROCESS>(
                        buffer + (i * entrySize));

                    var pid = (int)entry.ServiceStatusProcess.dwProcessId;
                    if (pid == 0)
                    {
                        // A stopped service has no process.
                        continue;
                    }

                    if (!map.TryGetValue(pid, out var names))
                    {
                        names = [];
                        map[pid] = names;
                    }

                    names.Add(entry.lpServiceName);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        finally
        {
            ServiceApi.CloseServiceHandle(manager);
        }

        return map;
    }
}
