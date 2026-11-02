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

    /// <summary>
    /// The same answer as a code the UI can translate, from
    /// <see cref="Ipc.ReasonCodes"/>. Null when rules can be written.
    ///
    /// Separate from the sentence above because the two have different readers: the
    /// sentence goes to the log in English, where it is easier to search; the code goes
    /// to the interface, which says it in the user's language.
    /// </summary>
    string? UnavailableCode { get; }

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

/// <summary>
/// A firewall operation that failed. Carries a reason code beside its message for the
/// same reason everything else does: the message goes to the English log, the code goes to
/// the interface, which says it in the user's language.
/// </summary>
public sealed class FirewallException(
    string message,
    string code = Ipc.ReasonCodes.BlockRuleFailed,
    Exception? inner = null)
    : Exception(message, inner)
{
    /// <summary>One of the blocking <see cref="Ipc.ReasonCodes"/>.</summary>
    public string Code { get; } = code;
}
