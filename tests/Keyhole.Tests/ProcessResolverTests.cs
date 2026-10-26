using System.Diagnostics;
using Keyhole.Core.Monitoring;
using Keyhole.Native;
using Xunit.Abstractions;

namespace Keyhole.Tests;

public class ProcessResolverTests(ITestOutputHelper output)
{
    private readonly ProcessResolver _resolver = new();

    [Fact]
    public void Resolves_the_test_process_itself()
    {
        var identity = _resolver.Resolve(Environment.ProcessId);

        output.WriteLine($"path={identity.ExecutablePath}");
        output.WriteLine($"name={identity.DisplayName}, publisher={identity.Publisher}");
        output.WriteLine($"signature={identity.Signature}, started={identity.StartTimeUtc:O}");

        Assert.Equal(Environment.ProcessId, identity.ProcessId);
        Assert.NotNull(identity.ExecutablePath);
        Assert.True(File.Exists(identity.ExecutablePath));
        Assert.False(identity.IsOpaque);
        Assert.NotNull(identity.StartTimeUtc);
    }

    [Fact]
    public void Start_time_matches_what_the_BCL_reports()
    {
        using var self = Process.GetCurrentProcess();
        var expected = self.StartTime.ToUniversalTime();

        var identity = _resolver.Resolve(Environment.ProcessId);

        Assert.NotNull(identity.StartTimeUtc);
        output.WriteLine($"BCL={expected:O} native={identity.StartTimeUtc:O}");

        // Both read the same kernel value; any real difference means the FILETIME
        // conversion is wrong, which would break PID-reuse detection.
        Assert.True(
            Math.Abs((identity.StartTimeUtc!.Value - expected).TotalSeconds) < 2,
            $"Start times differ: {identity.StartTimeUtc} vs {expected}");
    }

    [Fact]
    public void Signed_windows_binary_verifies_as_valid()
    {
        // explorer.exe ships signed by Microsoft and chains to a trusted root on any
        // healthy Windows install, so this exercises the success path of WinVerifyTrust.
        var explorer = Process.GetProcessesByName("explorer").FirstOrDefault();
        if (explorer is null)
        {
            output.WriteLine("explorer.exe not running; skipping.");
            return;
        }

        using (explorer)
        {
            var identity = _resolver.Resolve(explorer.Id);
            output.WriteLine($"{identity.DisplayName}: {identity.Signature}, publisher={identity.Publisher}");

            Assert.Equal(SignatureStatus.Valid, identity.Signature);
            Assert.Contains("Microsoft", identity.Publisher ?? "", StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void Unsigned_file_is_reported_as_unsigned()
    {
        // A plain file Keyhole just wrote carries no signature at all. This separates
        // "no signature" from "signature present but broken", which the UI must not conflate.
        var path = Path.Combine(Path.GetTempPath(), $"keyhole-unsigned-{Guid.NewGuid():n}.exe");
        File.WriteAllBytes(path, "MZ not a real executable"u8.ToArray());

        try
        {
            var status = new AuthenticodeVerifier().Verify(path);
            output.WriteLine($"status={status}");

            Assert.Equal(SignatureStatus.Unsigned, status);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Missing_file_is_unknown_not_unsigned()
    {
        var status = new AuthenticodeVerifier().Verify(@"C:\does\not\exist\anywhere.exe");

        // Claiming a file Keyhole cannot see is "unsigned" would be a false accusation.
        Assert.Equal(SignatureStatus.Unknown, status);
    }

    [Fact]
    public void Exited_process_resolves_without_throwing()
    {
        // A connection can outlive the process that owned it by a sampling interval,
        // so the resolver must tolerate a PID that is already gone.
        var identity = _resolver.Resolve(999_999);

        Assert.True(identity.IsOpaque);
        Assert.Equal("PID 999999", identity.DisplayName);
    }

    [Fact]
    public void Process_with_an_unreadable_path_still_gets_a_name()
    {
        // Unelevated, processes owned by other users deny the path query. Falling back to
        // the process list keeps the app list readable instead of showing bare PIDs.
        var unreadable = Process.GetProcesses()
            .Select(p =>
            {
                using (p)
                {
                    return _resolver.Resolve(p.Id);
                }
            })
            .Where(i => i.ExecutablePath is null && i.HostedServices.Count == 0)
            .Where(i => i.ProcessId is not (0 or 4))
            .ToList();

        if (unreadable.Count == 0)
        {
            output.WriteLine("Every process path was readable; nothing to check.");
            return;
        }

        output.WriteLine($"{unreadable.Count} process(es) with no readable path:");
        foreach (var identity in unreadable.Take(5))
        {
            output.WriteLine($"  PID {identity.ProcessId}: {identity.DisplayName}");
        }

        var bare = unreadable
            .Where(i => i.DisplayName == $"PID {i.ProcessId}")
            // A process that exited between the enumeration above and its resolution has
            // no name left to read, and a bare PID is then the honest answer rather than a
            // defect. The invariant that matters is about processes that are still there.
            .Where(i => IsRunning(i.ProcessId))
            .ToList();

        Assert.True(
            bare.Count == 0,
            $"{bare.Count} live process(es) fell back to a bare PID: " +
            string.Join(", ", bare.Take(5).Select(i => i.DisplayName)));
    }

    private static bool IsRunning(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            return !process.HasExited;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            return false;
        }
    }

    [Fact]
    public void Svchost_is_named_by_the_services_it_hosts()
    {
        var svchosts = Process.GetProcessesByName("svchost");
        if (svchosts.Length == 0)
        {
            output.WriteLine("No svchost processes; skipping.");
            return;
        }

        try
        {
            var named = svchosts
                .Select(p => _resolver.Resolve(p.Id))
                .Where(i => i.HostedServices.Count > 0)
                .ToList();

            output.WriteLine($"{named.Count} of {svchosts.Length} svchosts had service names.");
            foreach (var identity in named.Take(5))
            {
                output.WriteLine($"  PID {identity.ProcessId}: {identity.DisplayName}");
            }

            // If none resolved, the SCM enumeration silently failed and every system
            // connection would show as a bare "svchost.exe".
            Assert.NotEmpty(named);

            // The name must carry a service name, not the host binary and not a bare PID.
            // Unelevated, most svchosts have no readable path, so naming must not depend on one.
            Assert.All(named, i => Assert.NotEqual("svchost.exe", i.DisplayName));
            Assert.All(named, i => Assert.DoesNotMatch(@"^PID \d+$", i.DisplayName));
            Assert.All(named, i => Assert.Contains(i.HostedServices[0], i.DisplayName, StringComparison.Ordinal));
        }
        finally
        {
            foreach (var p in svchosts)
            {
                p.Dispose();
            }
        }
    }

    [Fact]
    public void Repeated_resolution_is_consistent()
    {
        var first = _resolver.Resolve(Environment.ProcessId);
        var second = _resolver.Resolve(Environment.ProcessId);

        Assert.Equal(first.ExecutablePath, second.ExecutablePath);
        Assert.Equal(first.DisplayName, second.DisplayName);
        Assert.Equal(first.StartTimeUtc, second.StartTimeUtc);
        Assert.Equal(first.Key, second.Key);
    }
}
