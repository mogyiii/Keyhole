using Keyhole.Core.Storage;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Keyhole.Core.Blocking;

/// <summary>
/// Creates and removes block rules, keeping Keyhole's record and the firewall in step.
///
/// Blocking is always a deliberate user action: there is no automatic or default-deny
/// behaviour anywhere in this class.
/// </summary>
public sealed class BlockingService(
    IFirewall firewall,
    RuleRepository rules,
    ILogger<BlockingService>? logger = null)
{
    private readonly ILogger _logger = logger ?? NullLogger<BlockingService>.Instance;

    public bool CanModifyRules => firewall.CanModifyRules;

    public string? UnavailableReason => firewall.UnavailableReason;

    public IReadOnlyList<BlockRule> ListRules() => rules.ListAll();

    /// <summary>
    /// Blocks an executable. The firewall is written first: if that fails there must be
    /// no stored rule claiming the app is blocked when it is not.
    /// </summary>
    public BlockRule Block(string executablePath, RuleDirection direction = RuleDirection.Outbound, string? note = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);

        if (!File.Exists(executablePath))
        {
            throw new BlockingException($"No executable at '{executablePath}'.");
        }

        if (!firewall.CanModifyRules)
        {
            throw new BlockingException(
                firewall.UnavailableReason ?? "Firewall rules cannot be modified.");
        }

        var rule = new BlockRule
        {
            ExecutablePath = executablePath,
            // Pinned now, while the user is looking at the thing they chose to block.
            Sha256 = ExecutableHasher.TryComputeSha256(executablePath),
            Direction = direction,
            Action = RuleAction.Block,
            IsEnabled = true,
            Note = note,
            CreatedUtc = DateTimeOffset.UtcNow,
        };

        var firewallRuleName = firewall.Apply(rule);
        var stored = rules.Upsert(rule with { FirewallRuleName = firewallRuleName });

        _logger.LogInformation(
            "Blocked {Path} ({Direction}), firewall rule '{Rule}'.",
            executablePath, direction, firewallRuleName);

        return stored;
    }

    /// <summary>
    /// Removes a rule. The firewall entry goes first, so a failure leaves the stored rule
    /// in place rather than losing the record of something still blocked.
    /// </summary>
    public bool Unblock(long ruleId)
    {
        var rule = rules.FindById(ruleId);
        if (rule is null)
        {
            return false;
        }

        if (!firewall.CanModifyRules)
        {
            throw new BlockingException(
                firewall.UnavailableReason ?? "Firewall rules cannot be modified.");
        }

        if (rule.FirewallRuleName is { } name)
        {
            firewall.Remove(name);
        }

        rules.Delete(ruleId);
        _logger.LogInformation("Unblocked {Path} (rule {Id}).", rule.ExecutablePath, ruleId);
        return true;
    }

    /// <summary>Enables or disables a rule without deleting it.</summary>
    public BlockRule SetEnabled(long ruleId, bool enabled)
    {
        var rule = rules.FindById(ruleId)
                   ?? throw new BlockingException($"No rule with id {ruleId}.");

        if (!firewall.CanModifyRules)
        {
            throw new BlockingException(
                firewall.UnavailableReason ?? "Firewall rules cannot be modified.");
        }

        var updated = rule with { IsEnabled = enabled };
        var firewallRuleName = firewall.Apply(updated);

        return rules.Upsert(updated with { FirewallRuleName = firewallRuleName });
    }

    /// <summary>
    /// Brings the firewall back in line with the stored rules, and reports anything that
    /// looks wrong.
    ///
    /// Run at startup because the two can drift while Keyhole is not running: a rule can be
    /// deleted by hand or by a firewall reset, and the user would never know their block had
    /// stopped applying. The stored record is treated as the intent and re-applied.
    /// </summary>
    public ReconciliationResult Reconcile()
    {
        if (!firewall.CanModifyRules)
        {
            return new ReconciliationResult([], [], [], firewall.UnavailableReason);
        }

        var stored = rules.ListAll();
        var restored = new List<BlockRule>();
        var removedOrphans = new List<string>();
        var tampered = new List<BlockRule>();

        List<FirewallRule> live;
        try
        {
            live = [.. firewall.ListKeyholeRules()];
        }
        catch (FirewallException ex)
        {
            _logger.LogError(ex, "Could not read firewall rules; skipping reconciliation.");
            return new ReconciliationResult([], [], [], ex.Message);
        }

        var liveByName = live
            .GroupBy(r => StripDirectionSuffix(r.Name), StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.ToList(), StringComparer.OrdinalIgnoreCase);

        foreach (var rule in stored)
        {
            var expectedName = rule.FirewallRuleName;

            if (expectedName is null || !liveByName.ContainsKey(expectedName))
            {
                // The user asked for this block and it is not in force. Re-apply rather
                // than drop the record: silently unblocking is the dangerous direction.
                try
                {
                    var name = firewall.Apply(rule);
                    rules.Upsert(rule with { FirewallRuleName = name });
                    restored.Add(rule);

                    _logger.LogWarning(
                        "Firewall rule for {Path} was missing and has been re-applied.",
                        rule.ExecutablePath);
                }
                catch (FirewallException ex)
                {
                    _logger.LogError(ex, "Could not re-apply the rule for {Path}.", rule.ExecutablePath);
                }
            }
            else
            {
                liveByName.Remove(expectedName);
            }

            if (ExecutableHasher.Verify(rule.ExecutablePath, rule.Sha256) == HashVerdict.Changed)
            {
                // Still blocked by path, but it is not the same binary any more.
                tampered.Add(rule);
                _logger.LogWarning(
                    "The executable at {Path} differs from the one this rule was created for.",
                    rule.ExecutablePath);
            }
        }

        // Keyhole-named rules with no stored counterpart are leftovers from a crash or an
        // uninstall. Only rules carrying Keyhole's prefix reach here, so nothing of the
        // user's own is ever touched.
        foreach (var orphanName in liveByName.Keys)
        {
            try
            {
                firewall.Remove(orphanName);
                removedOrphans.Add(orphanName);
                _logger.LogInformation("Removed orphaned firewall rule '{Name}'.", orphanName);
            }
            catch (FirewallException ex)
            {
                _logger.LogError(ex, "Could not remove orphaned rule '{Name}'.", orphanName);
            }
        }

        return new ReconciliationResult(restored, removedOrphans, tampered, null);
    }

    /// <summary>
    /// A bidirectional rule becomes two firewall entries named "… (in)" and "… (out)";
    /// both map back to the one stored rule.
    /// </summary>
    private static string StripDirectionSuffix(string name) =>
        name.EndsWith(" (in)", StringComparison.Ordinal) ||
        name.EndsWith(" (out)", StringComparison.Ordinal)
            ? name[..name.LastIndexOf(" (", StringComparison.Ordinal)]
            : name;
}

public sealed record ReconciliationResult(
    IReadOnlyList<BlockRule> Restored,
    IReadOnlyList<string> RemovedOrphans,
    IReadOnlyList<BlockRule> ChangedExecutables,
    string? SkippedReason)
{
    public bool DidAnything =>
        Restored.Count > 0 || RemovedOrphans.Count > 0 || ChangedExecutables.Count > 0;
}

public sealed class BlockingException(string message, Exception? inner = null)
    : Exception(message, inner);
