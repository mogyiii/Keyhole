using Keyhole.Core.Blocking;
using Keyhole.Core.Storage;
using Microsoft.Data.Sqlite;

namespace Keyhole.Tests;

public class BlockingServiceTests : IDisposable
{
    private readonly string _databaseFile =
        Path.Combine(Path.GetTempPath(), $"keyhole-rules-{Guid.NewGuid():n}.sqlite");

    private readonly string _exeDirectory =
        Path.Combine(Path.GetTempPath(), $"keyhole-exes-{Guid.NewGuid():n}");

    private readonly KeyholeDatabase _database;
    private readonly RuleRepository _rules;
    private readonly FakeFirewall _firewall = new();
    private readonly BlockingService _service;

    public BlockingServiceTests()
    {
        _database = new KeyholeDatabase(_databaseFile);
        new MigrationRunner(_database).Migrate();
        _rules = new RuleRepository(_database);
        _service = new BlockingService(_firewall, _rules);
        Directory.CreateDirectory(_exeDirectory);
    }

    private string MakeExe(string name = "sus.exe", string content = "binary contents")
    {
        var path = Path.Combine(_exeDirectory, name);
        File.WriteAllText(path, content);
        return path;
    }

    [Fact]
    public void Blocking_writes_the_firewall_and_stores_the_rule()
    {
        var exe = MakeExe();

        var rule = _service.Block(exe);

        Assert.True(rule.Id > 0);
        Assert.Equal(RuleAction.Block, rule.Action);
        Assert.True(rule.IsEnabled);
        Assert.NotNull(rule.FirewallRuleName);
        Assert.Single(_firewall.Applied);
        Assert.Single(_rules.ListAll());
    }

    [Fact]
    public void Blocking_pins_the_executable_hash()
    {
        var exe = MakeExe();

        var rule = _service.Block(exe);

        // Without this a user could rename a different binary onto the blocked path.
        Assert.NotNull(rule.Sha256);
        Assert.Equal(ExecutableHasher.TryComputeSha256(exe), rule.Sha256);
    }

    [Fact]
    public void Blocking_a_missing_executable_is_refused()
    {
        var ex = Assert.Throws<BlockingException>(() =>
            _service.Block(Path.Combine(_exeDirectory, "nope.exe")));

        Assert.Contains("No executable", ex.Message);
        Assert.Empty(_firewall.Applied);
        Assert.Empty(_rules.ListAll());
    }

    [Fact]
    public void No_rule_is_stored_when_the_firewall_write_fails()
    {
        var exe = MakeExe();
        _firewall.FailOnApply = true;

        Assert.Throws<FirewallException>(() => _service.Block(exe));

        // A stored rule with no firewall entry would tell the user an app is blocked
        // when it is not — the most dangerous possible inconsistency here.
        Assert.Empty(_rules.ListAll());
    }

    [Fact]
    public void Blocking_without_permission_is_refused_with_a_reason()
    {
        var exe = MakeExe();
        _firewall.CanModify = false;
        _firewall.Reason = "not elevated";

        var ex = Assert.Throws<BlockingException>(() => _service.Block(exe));

        Assert.Equal("not elevated", ex.Message);
        Assert.Empty(_rules.ListAll());
    }

    [Fact]
    public void Blocking_the_same_app_twice_keeps_one_rule()
    {
        var exe = MakeExe();

        _service.Block(exe);
        _service.Block(exe);

        Assert.Single(_rules.ListAll());
    }

    [Fact]
    public void Same_app_can_be_blocked_in_both_directions_separately()
    {
        var exe = MakeExe();

        _service.Block(exe, RuleDirection.Outbound);
        _service.Block(exe, RuleDirection.Inbound);

        Assert.Equal(2, _rules.ListAll().Count);
    }

    [Fact]
    public void Unblocking_removes_both_the_firewall_entry_and_the_rule()
    {
        var exe = MakeExe();
        var rule = _service.Block(exe);

        Assert.True(_service.Unblock(rule.Id));

        Assert.Empty(_rules.ListAll());
        Assert.Empty(_firewall.Live);
    }

    [Fact]
    public void Unblocking_an_unknown_rule_reports_false()
    {
        Assert.False(_service.Unblock(12345));
    }

    [Fact]
    public void Disabling_keeps_the_rule_but_marks_it_off()
    {
        var exe = MakeExe();
        var rule = _service.Block(exe);

        var updated = _service.SetEnabled(rule.Id, false);

        Assert.False(updated.IsEnabled);
        Assert.Single(_rules.ListAll());
        Assert.False(_firewall.Live.Single().IsEnabled);
    }

    // --- Reconciliation ---

    [Fact]
    public void Reconcile_restores_a_rule_deleted_behind_Keyholes_back()
    {
        var exe = MakeExe();
        _service.Block(exe);

        // Someone deleted it in wf.msc, or a firewall reset wiped it.
        _firewall.Live.Clear();

        var result = _service.Reconcile();

        // Silently leaving the app unblocked is the dangerous direction, so the stored
        // intent wins and the rule goes back.
        Assert.Single(result.Restored);
        Assert.Single(_firewall.Live);
    }

    [Fact]
    public void Reconcile_leaves_a_healthy_rule_alone()
    {
        var exe = MakeExe();
        _service.Block(exe);
        _firewall.Applied.Clear();

        var result = _service.Reconcile();

        Assert.Empty(result.Restored);
        Assert.Empty(result.RemovedOrphans);
        Assert.Empty(_firewall.Applied);
    }

    [Fact]
    public void Reconcile_removes_a_Keyhole_rule_with_no_stored_counterpart()
    {
        // Left behind by a crash between writing the firewall and storing the rule.
        _firewall.Live.Add(new FirewallRule
        {
            Name = "Keyhole - ghost.exe [abcd1234]",
            ApplicationPath = @"C:\ghost.exe",
            Direction = RuleDirection.Outbound,
            Action = RuleAction.Block,
            IsEnabled = true,
        });

        var result = _service.Reconcile();

        Assert.Single(result.RemovedOrphans);
        Assert.Empty(_firewall.Live);
    }

    [Fact]
    public void Reconcile_matches_both_halves_of_a_bidirectional_rule()
    {
        var exe = MakeExe();
        var rule = _service.Block(exe, RuleDirection.Both);

        // A "both" rule becomes two firewall entries; neither is an orphan.
        _firewall.Live.Clear();
        _firewall.Live.Add(Entry($"{rule.FirewallRuleName} (out)", exe));
        _firewall.Live.Add(Entry($"{rule.FirewallRuleName} (in)", exe));

        var result = _service.Reconcile();

        Assert.Empty(result.RemovedOrphans);
        Assert.Empty(result.Restored);
    }

    [Fact]
    public void Reconcile_flags_an_executable_that_changed_since_the_rule_was_made()
    {
        var exe = MakeExe(content: "original binary");
        _service.Block(exe);

        // A different binary now sits at the blocked path.
        File.WriteAllText(exe, "something else entirely");

        var result = _service.Reconcile();

        Assert.Single(result.ChangedExecutables);

        // The block still applies to the path; the user is told what changed, not
        // silently left with a rule that means something different now.
        Assert.Single(_firewall.Live);
    }

    [Fact]
    public void Reconcile_does_not_flag_an_unchanged_executable()
    {
        var exe = MakeExe();
        _service.Block(exe);

        var result = _service.Reconcile();

        Assert.Empty(result.ChangedExecutables);
    }

    [Fact]
    public void Reconcile_reports_why_it_was_skipped_without_permission()
    {
        _firewall.CanModify = false;
        _firewall.Reason = "not elevated";

        var result = _service.Reconcile();

        Assert.Equal("not elevated", result.SkippedReason);
        Assert.False(result.DidAnything);
    }

    [Fact]
    public void Reconcile_survives_a_firewall_that_cannot_be_read()
    {
        var exe = MakeExe();
        _service.Block(exe);
        _firewall.FailOnList = true;

        var result = _service.Reconcile();

        // Startup must not fail because the firewall is unhappy.
        Assert.NotNull(result.SkippedReason);
    }

    private static FirewallRule Entry(string name, string path) => new()
    {
        Name = name,
        ApplicationPath = path,
        Direction = RuleDirection.Outbound,
        Action = RuleAction.Block,
        IsEnabled = true,
    };

    /// <summary>
    /// In-memory firewall. Lets reconciliation — the part most likely to go wrong and
    /// the hardest to trigger on a real machine — be tested exactly and without elevation.
    /// </summary>
    private sealed class FakeFirewall : IFirewall
    {
        public List<FirewallRule> Live { get; } = [];
        public List<BlockRule> Applied { get; } = [];

        public bool CanModify { get; set; } = true;
        public string? Reason { get; set; }
        public bool FailOnApply { get; set; }
        public bool FailOnList { get; set; }

        public bool CanModifyRules => CanModify;
        public string? UnavailableReason => Reason;

        public IReadOnlyList<FirewallRule> ListKeyholeRules() =>
            FailOnList ? throw new FirewallException("simulated") : Live;

        public string Apply(BlockRule rule)
        {
            if (FailOnApply)
            {
                throw new FirewallException("simulated apply failure");
            }

            Applied.Add(rule);

            var name = $"Keyhole - {Path.GetFileName(rule.ExecutablePath)} [{rule.Direction}]";
            Live.RemoveAll(r => r.Name == name);
            Live.Add(new FirewallRule
            {
                Name = name,
                ApplicationPath = rule.ExecutablePath,
                Direction = rule.Direction,
                Action = rule.Action,
                IsEnabled = rule.IsEnabled,
            });

            return name;
        }

        public void Remove(string firewallRuleName) =>
            Live.RemoveAll(r =>
                r.Name == firewallRuleName ||
                r.Name == $"{firewallRuleName} (in)" ||
                r.Name == $"{firewallRuleName} (out)");
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();

        foreach (var suffix in new[] { "", "-wal", "-shm" })
        {
            try
            {
                File.Delete(_databaseFile + suffix);
            }
            catch (IOException)
            {
                // A leaked handle must not mask a real test failure.
            }
        }

        try
        {
            Directory.Delete(_exeDirectory, recursive: true);
        }
        catch (IOException)
        {
            // Same.
        }
    }
}
