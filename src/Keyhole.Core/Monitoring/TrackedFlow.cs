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

/// <summary>
/// One row of the host list: everything one destination is receiving, from every
/// application at once.
///
/// The app list answers "what is this program doing". This answers the same question from
/// the other end, which is where an unexpected destination shows up: a host that three
/// unrelated programs are all talking to is interesting in a way that none of those three
/// programs looks interesting on its own.
/// </summary>
public sealed record HostActivity
{
    /// <summary>
    /// The resolved hostname, or the address when reverse DNS produced nothing. This is
    /// what rows are grouped by, so a host behind several addresses collapses into one row
    /// and an unresolvable address still gets its own.
    /// </summary>
    public required string Host { get; init; }

    /// <summary>
    /// Addresses seen for this host. More than one is normal for anything behind a CDN,
    /// and showing the count is how the user knows the row is an aggregate.
    /// </summary>
    public IReadOnlyList<string> Addresses { get; init; } = [];

    /// <summary>Ports talked to, which is what distinguishes a web host from a mail one.</summary>
    public IReadOnlyList<int> Ports { get; init; } = [];

    /// <summary>
    /// Applications talking to this host, by display name. The interesting number: one
    /// destination shared by several unrelated programs is worth a second look.
    /// </summary>
    public IReadOnlyList<string> Applications { get; init; } = [];

    public required int ActiveConnections { get; init; }
    public required int TotalConnections { get; init; }
    public required long BytesSent { get; init; }
    public required long BytesReceived { get; init; }

    public required DateTimeOffset FirstSeenUtc { get; init; }
    public required DateTimeOffset LastActiveUtc { get; init; }

    /// <summary>Total in both directions, which is what the list is ranked by.</summary>
    public long TotalBytes => BytesSent + BytesReceived;
}
