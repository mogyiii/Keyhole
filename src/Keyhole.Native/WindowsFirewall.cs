using System.Collections;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Keyhole.Core.Blocking;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Keyhole.Native;

/// <summary>
/// Windows Firewall via the INetFwPolicy2 COM API.
///
/// Chosen over writing WFP filters directly because these rules survive a reboot and a
/// Keyhole uninstall without a driver: the OS owns them. The cost is that matching is by
/// executable path only, which is why <see cref="BlockRule.Sha256"/> exists separately.
///
/// Accessed through late-bound COM: the interop assembly (FirewallAPI) is not available
/// as a package for modern .NET, and the surface used here is four properties and two
/// methods.
/// </summary>
public sealed class WindowsFirewall : IFirewall
{
    /// <summary>
    /// Prefix on every rule Keyhole creates. Reconciliation and removal only ever touch
    /// rules carrying it, so a user's own firewall rules are never disturbed.
    /// </summary>
    public const string RuleNamePrefix = "Keyhole - ";

    private const string FirewallPolicyProgId = "HNetCfg.FwPolicy2";
    private const string FirewallRuleProgId = "HNetCfg.FWRule";

    // NET_FW_RULE_DIRECTION
    private const int DirectionIn = 1;
    private const int DirectionOut = 2;

    // NET_FW_ACTION
    private const int ActionBlock = 0;
    private const int ActionAllow = 1;

    // NET_FW_PROFILE_TYPE2: domain | private | public. A rule bound to only the current
    // profile would silently stop applying when the machine joins a different network.
    private const int ProfileAll = 0x7FFFFFFF;

    private readonly ILogger _logger;

    public WindowsFirewall(ILogger<WindowsFirewall>? logger = null)
    {
        _logger = logger ?? NullLogger<WindowsFirewall>.Instance;

        if (!IsElevated())
        {
            UnavailableReason = "Creating firewall rules needs administrator rights; the service is not elevated.";
            return;
        }

        try
        {
            // Proves the COM server is reachable before any rule is attempted, so the
            // failure surfaces at startup rather than when the user clicks Block.
            _ = CreatePolicy();
            CanModifyRules = true;
        }
        catch (Exception ex)
        {
            UnavailableReason = $"Windows Firewall is not reachable: {ex.Message}";
            _logger.LogError(ex, "Could not reach the Windows Firewall COM API.");
        }
    }

    public bool CanModifyRules { get; }

    public string? UnavailableReason { get; }

    public IReadOnlyList<FirewallRule> ListKeyholeRules()
    {
        var results = new List<FirewallRule>();

        try
        {
            dynamic policy = CreatePolicy();
            dynamic rules = policy.Rules;

            // Rules is a COM collection; IEnumerable is the only way to walk it.
            foreach (var item in (IEnumerable)rules)
            {
                dynamic rule = item;

                string name;
                try
                {
                    name = rule.Name as string ?? "";
                }
                catch (Exception)
                {
                    // A malformed rule from some other product must not abort enumeration.
                    continue;
                }

                if (!name.StartsWith(RuleNamePrefix, StringComparison.Ordinal))
                {
                    continue;
                }

                results.Add(new FirewallRule
                {
                    Name = name,
                    ApplicationPath = SafeString(() => rule.ApplicationName) ?? "",
                    Direction = (int)rule.Direction == DirectionIn ? RuleDirection.Inbound : RuleDirection.Outbound,
                    Action = (int)rule.Action == ActionBlock ? RuleAction.Block : RuleAction.Allow,
                    IsEnabled = (bool)rule.Enabled,
                });
            }
        }
        catch (Exception ex)
        {
            throw new FirewallException("Could not enumerate firewall rules.", ex);
        }

        return results;
    }

    public string Apply(BlockRule rule)
    {
        EnsureModifiable();

        var baseName = BuildRuleName(rule);

        try
        {
            dynamic policy = CreatePolicy();

            // "Both" is two firewall rules: the API has no bidirectional direction value.
            var directions = rule.Direction switch
            {
                RuleDirection.Both => new[] { DirectionOut, DirectionIn },
                RuleDirection.Inbound => [DirectionIn],
                _ => new[] { DirectionOut },
            };

            foreach (var direction in directions)
            {
                var name = directions.Length == 1
                    ? baseName
                    : $"{baseName} ({(direction == DirectionIn ? "in" : "out")})";

                // Replace rather than duplicate: applying the same rule twice must not
                // leave two firewall entries that removal would only half clean up.
                RemoveByName(policy, name);

                dynamic firewallRule = CreateRule();
                firewallRule.Name = name;
                firewallRule.Description = $"Created by Keyhole for {rule.ExecutablePath}";
                firewallRule.ApplicationName = rule.ExecutablePath;
                firewallRule.Direction = direction;
                firewallRule.Action = rule.Action == RuleAction.Block ? ActionBlock : ActionAllow;
                firewallRule.Enabled = rule.IsEnabled;
                firewallRule.Profiles = ProfileAll;
                firewallRule.Grouping = "Keyhole";

                policy.Rules.Add(firewallRule);
            }

            _logger.LogInformation(
                "Applied firewall rule '{Name}' ({Direction}) for {Path}.",
                baseName, rule.Direction, rule.ExecutablePath);

            return baseName;
        }
        catch (Exception ex) when (ex is not FirewallException)
        {
            throw new FirewallException(
                $"Could not apply a firewall rule for '{rule.ExecutablePath}'.", ex);
        }
    }

    public void Remove(string firewallRuleName)
    {
        EnsureModifiable();

        try
        {
            dynamic policy = CreatePolicy();

            // Covers both the single-direction name and the "(in)"/"(out)" pair.
            RemoveByName(policy, firewallRuleName);
            RemoveByName(policy, $"{firewallRuleName} (in)");
            RemoveByName(policy, $"{firewallRuleName} (out)");

            _logger.LogInformation("Removed firewall rule '{Name}'.", firewallRuleName);
        }
        catch (Exception ex)
        {
            throw new FirewallException($"Could not remove firewall rule '{firewallRuleName}'.", ex);
        }
    }

    /// <summary>
    /// Builds a stable, unique rule name. The path is included so two rules for different
    /// executables with the same file name do not collide, and hashed so the name stays
    /// within the firewall's length limit.
    /// </summary>
    internal static string BuildRuleName(BlockRule rule)
    {
        // Windows paths are case-insensitive, so the whole name — not just the hash — has
        // to be case-independent. Keeping the original spelling here made "C:\One\app.exe"
        // and "C:\One\App.exe" produce two different rule names for one executable, which
        // reconciliation would then see as a missing rule plus an orphan.
        var normalised = rule.ExecutablePath.ToLowerInvariant();
        var fileName = Path.GetFileName(normalised);

        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(normalised));
        var pathHash = Convert.ToHexString(digest.AsSpan(0, 4)).ToLowerInvariant();

        return string.Create(
            CultureInfo.InvariantCulture,
            $"{RuleNamePrefix}{fileName} [{pathHash}]");
    }

    private static void RemoveByName(dynamic policy, string name)
    {
        try
        {
            policy.Rules.Remove(name);
        }
        catch (Exception)
        {
            // Remove throws when the rule is absent, which is the normal case here.
        }
    }

    private void EnsureModifiable()
    {
        if (!CanModifyRules)
        {
            throw new FirewallException(
                UnavailableReason ?? "Firewall rules cannot be modified.");
        }
    }

    private static object CreatePolicy() => CreateComObject(FirewallPolicyProgId);

    private static object CreateRule() => CreateComObject(FirewallRuleProgId);

    private static object CreateComObject(string progId)
    {
        var type = Type.GetTypeFromProgID(progId, throwOnError: false)
                   ?? throw new FirewallException($"COM class '{progId}' is not registered.");

        return Activator.CreateInstance(type)
               ?? throw new FirewallException($"Could not create an instance of '{progId}'.");
    }

    private static string? SafeString(Func<dynamic> read)
    {
        try
        {
            return read() as string;
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
}
