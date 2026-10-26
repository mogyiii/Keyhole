namespace Keyhole.Core.Monitoring;

/// <summary>
/// A connection the tracker is following, enriched with who owns it and who it talks to.
/// </summary>
public sealed record TrackedFlow
{
    public required ConnectionKey Key { get; init; }
    public required NetworkConnection Connection { get; init; }
    public required ProcessIdentity Process { get; init; }

    public required DateTimeOffset StartedUtc { get; init; }
    public required DateTimeOffset LastSeenUtc { get; init; }

    /// <summary>Set when the connection disappeared from the socket table.</summary>
    public DateTimeOffset? EndedUtc { get; init; }

    /// <summary>
    /// Reverse-DNS name, filled in asynchronously. Null until the lookup lands, so the UI
    /// shows the address first and the name a moment later rather than stalling.
    /// </summary>
    public string? RemoteHostname { get; init; }

    public long BytesSent { get; init; }
    public long BytesReceived { get; init; }

    public bool IsActive => EndedUtc is null;
}

/// <summary>
/// One row of the app list: everything a single program is doing on the network.
/// </summary>
public sealed record AppActivity
{
    /// <summary>Current upload rate in bytes per second.</summary>
    public double SentRate { get; init; }

    /// <summary>Current download rate in bytes per second.</summary>
    public double ReceivedRate { get; init; }

    public required string DisplayName { get; init; }
    public string? ExecutablePath { get; init; }
    public string? Publisher { get; init; }
    public required SignatureStatus Signature { get; init; }

    public required int ActiveConnections { get; init; }
    public required int TotalConnections { get; init; }
    public required long BytesSent { get; init; }
    public required long BytesReceived { get; init; }

    public required DateTimeOffset FirstSeenUtc { get; init; }
    public required DateTimeOffset LastActiveUtc { get; init; }

    /// <summary>Distinct remote hosts, most recent first. Capped for the list view.</summary>
    public IReadOnlyList<string> RecentRemoteHosts { get; init; } = [];

    /// <summary>PIDs currently contributing. One program can run as several processes.</summary>
    public IReadOnlyList<int> ProcessIds { get; init; } = [];
}
