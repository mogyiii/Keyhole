namespace Keyhole.Core.Blocking;

/// <summary>
/// The host firewall. Abstracted so rule logic — reconciliation especially — can be
/// tested without elevation and without touching the machine's real firewall.
/// </summary>
public interface IFirewall
{
    /// <summary>
    /// True when rules can actually be written. Enumeration works for any user, but
    /// creating and deleting rules needs administrator rights.
    /// </summary>
    bool CanModifyRules { get; }

    /// <summary>Why rules cannot be written, or null when they can.</summary>
    string? UnavailableReason { get; }

    /// <summary>Every Keyhole-owned rule currently present in the firewall.</summary>
    IReadOnlyList<FirewallRule> ListKeyholeRules();

    /// <summary>
    /// Creates or replaces a rule. Returns the firewall rule name so it can be stored
    /// alongside the Keyhole rule and reconciled later.
    /// </summary>
    string Apply(BlockRule rule);

    /// <summary>Removes a rule by firewall rule name. Succeeds if it was already gone.</summary>
    void Remove(string firewallRuleName);
}

public sealed class FirewallException(string message, Exception? inner = null)
    : Exception(message, inner);
