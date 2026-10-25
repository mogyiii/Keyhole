using System.Net;

namespace Keyhole.Core.Monitoring;

/// <summary>
/// Turns remote IPs into hostnames. Lookups happen in the background: the sampling loop
/// must never wait on DNS, or one unreachable resolver would stall all monitoring.
/// </summary>
public interface IHostnameResolver
{
    /// <summary>
    /// Returns a cached hostname, or null if not yet known. Non-blocking: a miss schedules
    /// a background lookup whose result shows up on a later sample.
    /// </summary>
    string? TryGet(IPAddress address);
}
