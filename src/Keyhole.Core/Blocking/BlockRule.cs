namespace Keyhole.Core.Blocking;

public enum RuleDirection
{
    Outbound,
    Inbound,
    Both,
}

public enum RuleAction
{
    Block,
    Allow,
}

/// <summary>
/// A rule the user created. Keyhole only ever creates these deliberately: there is no
/// deny-by-default mode, so every rule here is one somebody asked for.
/// </summary>
public sealed record BlockRule
{
    public long Id { get; init; }

    public required string ExecutablePath { get; init; }

    /// <summary>
    /// Hash of the executable when the rule was created. The firewall matches on path
    /// alone, so this is what lets Keyhole notice that the binary behind a blocked path
    /// has been swapped for a different one.
    /// </summary>
    public string? Sha256 { get; init; }

    public required RuleDirection Direction { get; init; }

    public RuleAction Action { get; init; } = RuleAction.Block;

    public bool IsEnabled { get; init; } = true;

    public string? Note { get; init; }

    public DateTimeOffset CreatedUtc { get; init; }

    /// <summary>Name of the backing Windows Firewall rule, so orphans can be reconciled.</summary>
    public string? FirewallRuleName { get; init; }

    public string DisplayName => Path.GetFileName(ExecutablePath);
}

/// <summary>What a rule looks like to the firewall, independent of Keyhole's storage.</summary>
public sealed record FirewallRule
{
    public required string Name { get; init; }
    public required string ApplicationPath { get; init; }
    public required RuleDirection Direction { get; init; }
    public required RuleAction Action { get; init; }
    public required bool IsEnabled { get; init; }
}
