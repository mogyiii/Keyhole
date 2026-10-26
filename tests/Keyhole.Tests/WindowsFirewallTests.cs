using System.Security.Principal;
using Keyhole.Core.Blocking;
using Keyhole.Native;
using Xunit.Abstractions;

namespace Keyhole.Tests;

/// <summary>
/// Exercises the real COM interop. Writing rules needs elevation, but enumeration does
/// not, which is enough to prove the dynamic dispatch and property marshalling work —
/// the parts most likely to be silently wrong.
/// </summary>
public class WindowsFirewallTests(ITestOutputHelper output)
{
    private static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    [Fact]
    public void Enumeration_reaches_the_firewall_COM_api()
    {
        var firewall = new WindowsFirewall();

        // Reads work for any user. If the COM plumbing were wrong this would throw
        // rather than return an empty list.
        var rules = firewall.ListKeyholeRules();

        output.WriteLine($"elevated={IsElevated()} keyhole rules={rules.Count}");
        foreach (var rule in rules.Take(5))
        {
            output.WriteLine($"  {rule.Name} -> {rule.ApplicationPath} ({rule.Direction}, {rule.Action})");
        }

        Assert.NotNull(rules);
    }

    [Fact]
    public void Enumeration_returns_only_Keyhole_rules()
    {
        var rules = new WindowsFirewall().ListKeyholeRules();

        // A machine has hundreds of firewall rules. Touching one that is not Keyhole's
        // during reconciliation would break something the user set up themselves.
        Assert.All(rules, r =>
            Assert.StartsWith(WindowsFirewall.RuleNamePrefix, r.Name, StringComparison.Ordinal));
    }

    [Fact]
    public void Modification_is_refused_with_a_reason_when_not_elevated()
    {
        if (IsElevated())
        {
            output.WriteLine("Session is elevated; the refusal path cannot be exercised here.");
            return;
        }

        var firewall = new WindowsFirewall();

        Assert.False(firewall.CanModifyRules);
        Assert.False(string.IsNullOrWhiteSpace(firewall.UnavailableReason));
        output.WriteLine($"reason: {firewall.UnavailableReason}");

        var rule = new BlockRule { ExecutablePath = @"C:\nope.exe", Direction = RuleDirection.Outbound };
        Assert.Throws<FirewallException>(() => firewall.Apply(rule));
    }

    [Fact]
    public void Rule_names_are_stable_across_calls()
    {
        var rule = new BlockRule
        {
            ExecutablePath = @"C:\Program Files\Thing\thing.exe",
            Direction = RuleDirection.Outbound,
        };

        var first = WindowsFirewall.BuildRuleName(rule);
        var second = WindowsFirewall.BuildRuleName(rule);

        // Reconciliation matches stored rules to firewall rules by name. A name derived
        // from string.GetHashCode would differ between processes because .NET randomises
        // string hashing, orphaning every rule on restart.
        Assert.Equal(first, second);
        output.WriteLine(first);
    }

    [Fact]
    public void Rule_name_for_a_known_path_is_a_fixed_constant()
    {
        var rule = new BlockRule
        {
            ExecutablePath = @"C:\Program Files\Thing\thing.exe",
            Direction = RuleDirection.Outbound,
        };

        // Hard-coded rather than recomputed: a self-consistent check would pass even if
        // the name became process-dependent again. This value was produced by the
        // SHA-256 implementation and must not drift.
        Assert.Equal("Keyhole - thing.exe [104cbc7c]", WindowsFirewall.BuildRuleName(rule));
    }

    [Fact]
    public void Rule_names_differ_for_same_named_executables_in_different_folders()
    {
        var a = WindowsFirewall.BuildRuleName(new BlockRule
        {
            ExecutablePath = @"C:\One\app.exe",
            Direction = RuleDirection.Outbound,
        });

        var b = WindowsFirewall.BuildRuleName(new BlockRule
        {
            ExecutablePath = @"C:\Two\app.exe",
            Direction = RuleDirection.Outbound,
        });

        // Colliding names would make blocking one app silently replace the other's rule.
        Assert.NotEqual(a, b);
        output.WriteLine($"{a}\n{b}");
    }

    [Fact]
    public void Rule_name_ignores_path_casing()
    {
        var lower = WindowsFirewall.BuildRuleName(new BlockRule
        {
            ExecutablePath = @"c:\one\app.exe",
            Direction = RuleDirection.Outbound,
        });

        var upper = WindowsFirewall.BuildRuleName(new BlockRule
        {
            ExecutablePath = @"C:\One\App.exe",
            Direction = RuleDirection.Outbound,
        });

        // Windows paths are case-insensitive; two spellings must not become two rules.
        Assert.Equal(lower, upper);
    }
}
