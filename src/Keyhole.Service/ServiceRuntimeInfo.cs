using System.Reflection;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace Keyhole.Service;

/// <summary>
/// Facts about this service process, captured once at startup. Registered as a singleton so
/// handlers report a stable start time rather than recomputing it per call.
/// </summary>
public sealed class ServiceRuntimeInfo
{
    public ServiceRuntimeInfo()
    {
        StartedAtUtc = DateTimeOffset.UtcNow;
        Version = Assembly.GetExecutingAssembly()
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
            ?? "0.0.0-unknown";
        IsElevated = DetectElevation();
    }

    public DateTimeOffset StartedAtUtc { get; }

    public string Version { get; }

    /// <summary>
    /// Whether the process holds administrator rights. Everything from M2 on (ETW sessions,
    /// firewall rules, capture) needs this, so the UI should warn loudly when it is false.
    /// </summary>
    public bool IsElevated { get; }

    [SupportedOSPlatform("windows")]
    private static bool DetectElevation()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
}
