namespace Keyhole.Core.Monitoring;

/// <summary>
/// What Keyhole knows about the program behind a connection.
/// </summary>
public sealed record ProcessIdentity
{
    public required int ProcessId { get; init; }

    /// <summary>Full path to the executable, or null when it could not be read.</summary>
    public string? ExecutablePath { get; init; }

    /// <summary>Best available name for the UI: product name, else file name, else "PID n".</summary>
    public required string DisplayName { get; init; }

    /// <summary>Company from the version resource. Not proof of anything on its own.</summary>
    public string? Publisher { get; init; }

    public SignatureStatus Signature { get; init; } = SignatureStatus.Unknown;

    /// <summary>
    /// Process start time. Combined with the PID this makes a stable identity:
    /// Windows reuses PIDs, so a PID alone would let a new process inherit the
    /// history and rules of a dead one.
    /// </summary>
    public DateTime? StartTimeUtc { get; init; }

    /// <summary>
    /// For svchost and similar hosts, the services running inside it. Without this every
    /// such connection reads as "svchost.exe" and tells the user nothing.
    /// </summary>
    public IReadOnlyList<string> HostedServices { get; init; } = [];

    /// <summary>True when the path could not be read, usually a protected system process.</summary>
    public bool IsOpaque => ExecutablePath is null;

    public ProcessKey Key => new(ProcessId, StartTimeUtc);
}

/// <summary>
/// Identifies a process run, not just a slot in the PID table.
/// </summary>
public readonly record struct ProcessKey(int ProcessId, DateTime? StartTimeUtc);

public enum SignatureStatus
{
    /// <summary>Not checked, or the check could not run.</summary>
    Unknown,

    /// <summary>Authenticode signature present and chains to a trusted root.</summary>
    Valid,

    /// <summary>Signature present but untrusted, expired or tampered with.</summary>
    Invalid,

    /// <summary>No signature at all.</summary>
    Unsigned,
}
