using System.Diagnostics;
using Keyhole.Core.Monitoring;
using Keyhole.Native.Interop;
using Microsoft.Win32.SafeHandles;

namespace Keyhole.Native;

/// <summary>
/// Resolves PIDs to recognisable program identities, caching by process run so repeated
/// sampling costs almost nothing.
/// </summary>
public sealed class ProcessResolver(
    AuthenticodeVerifier? signatures = null,
    ServiceNameResolver? services = null) : IProcessResolver
{
    private readonly AuthenticodeVerifier _signatures = signatures ?? new AuthenticodeVerifier();
    private readonly ServiceNameResolver _services = services ?? new ServiceNameResolver();

    private readonly Dictionary<ProcessKey, ProcessIdentity> _cache = [];
    private readonly Lock _gate = new();

    private const int MaxCacheEntries = 4096;

    public ProcessIdentity Resolve(int processId)
    {
        // PID 0 and 4 are the idle and system processes; they own sockets but have no
        // image to read, so short-circuit rather than failing an OpenProcess every pass.
        if (processId is 0 or 4)
        {
            return new ProcessIdentity
            {
                ProcessId = processId,
                DisplayName = processId == 0 ? "System Idle Process" : "System",
                Signature = SignatureStatus.Unknown,
            };
        }

        var startTime = TryGetStartTimeUtc(processId);
        var key = new ProcessKey(processId, startTime);

        lock (_gate)
        {
            if (_cache.TryGetValue(key, out var cached))
            {
                // Hosted services are refreshed separately: a svchost can gain or lose a
                // service without restarting, so that part of the identity is not stable.
                return cached with { HostedServices = _services.GetServices(processId) };
            }
        }

        var identity = ResolveUncached(processId, startTime);

        lock (_gate)
        {
            if (_cache.Count >= MaxCacheEntries)
            {
                _cache.Clear();
            }

            _cache[key] = identity;
        }

        return identity;
    }

    private ProcessIdentity ResolveUncached(int processId, DateTime? startTime)
    {
        var path = TryGetExecutablePath(processId);
        var hostedServices = _services.GetServices(processId);

        string? publisher = null;
        string? productName = null;

        if (path is not null)
        {
            try
            {
                var versionInfo = FileVersionInfo.GetVersionInfo(path);
                publisher = NullIfBlank(versionInfo.CompanyName);
                productName = NullIfBlank(versionInfo.FileDescription) ?? NullIfBlank(versionInfo.ProductName);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // A missing or unreadable version resource is normal; the file name still works.
            }
        }

        return new ProcessIdentity
        {
            ProcessId = processId,
            ExecutablePath = path,
            DisplayName = BuildDisplayName(processId, path, productName, hostedServices),
            Publisher = publisher,
            Signature = _signatures.Verify(path),
            StartTimeUtc = startTime,
            HostedServices = hostedServices,
        };
    }

    /// <summary>
    /// Picks the most informative name available. A service host is named by what it hosts,
    /// because "svchost.exe" tells the user nothing about which traffic they are looking at.
    /// </summary>
    private static string BuildDisplayName(
        int processId,
        string? path,
        string? productName,
        IReadOnlyList<string> hostedServices)
    {
        var fileName = path is null ? null : Path.GetFileName(path);
        var isServiceHost = string.Equals(fileName, "svchost.exe", StringComparison.OrdinalIgnoreCase);

        // Service names come from the SCM, which answers for processes Keyhole cannot open.
        // Unelevated, most system processes have no readable path, and requiring one here
        // would label the bulk of a machine's traffic "PID 1792".
        if (hostedServices.Count > 0 && (isServiceHost || path is null))
        {
            var suffix = isServiceHost ? "svchost" : "service";
            return hostedServices.Count == 1
                ? $"{hostedServices[0]} ({suffix})"
                : $"{string.Join(", ", hostedServices.Take(3))}{(hostedServices.Count > 3 ? ", …" : "")} ({suffix})";
        }

        return productName ?? fileName ?? $"PID {processId}";
    }

    private static string? TryGetExecutablePath(int processId)
    {
        using var handle = ProcessApi.OpenProcess(
            ProcessApi.PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)processId);

        if (handle.IsInvalid)
        {
            // Protected processes and anything that exited between the socket read and
            // now land here. Not an error worth surfacing.
            return null;
        }

        var buffer = new char[1024];
        var size = (uint)buffer.Length;

        return ProcessApi.QueryFullProcessImageName(handle, 0, buffer, ref size)
            ? new string(buffer, 0, (int)size)
            : null;
    }

    private static DateTime? TryGetStartTimeUtc(int processId)
    {
        using var handle = ProcessApi.OpenProcess(
            ProcessApi.PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)processId);

        if (handle.IsInvalid)
        {
            return null;
        }

        return ProcessApi.GetProcessTimes(handle, out var creation, out _, out _, out _)
            ? DateTime.FromFileTimeUtc(creation)
            : null;
    }

    private static string? NullIfBlank(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
