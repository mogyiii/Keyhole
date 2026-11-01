using System.Diagnostics;
using Keyhole.Native;

namespace Keyhole.Tests;

/// <summary>
/// Which processes a capture counts as "the application".
///
/// Tested against real processes, because the whole point is how Windows reports parentage
/// and start times — a fake would only re-state the assumptions being questioned. The
/// processes are throwaway cmd.exe instances that sleep and are killed afterwards.
/// </summary>
public class ProcessTreeReaderTests : IDisposable
{
    private readonly List<Process> _started = [];

    private static string Cmd => Path.Combine(Environment.SystemDirectory, "cmd.exe");

    /// <summary>Starts a cmd.exe that lives long enough to be looked at.</summary>
    private Process Spawn()
    {
        var process = Process.Start(new ProcessStartInfo
        {
            FileName = Cmd,
            Arguments = "/c ping -n 20 127.0.0.1",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
        })!;

        _started.Add(process);
        return process;
    }

    [Fact]
    public void The_launched_process_is_always_in_scope()
    {
        var process = Spawn();

        var owners = new ProcessTreeReader().DescendantsOf(process.Id, Cmd);

        Assert.Contains(process.Id, owners);
    }

    [Fact]
    public void Children_are_in_scope()
    {
        // cmd.exe runs ping as a child, which is the shape that matters: a browser's
        // network work happens in children, so a scope of one process records nothing.
        var process = Spawn();

        // Give the child time to appear in the process list.
        Thread.Sleep(1500);

        var owners = new ProcessTreeReader().DescendantsOf(process.Id, Cmd);

        var children = Process.GetProcessesByName("PING")
            .Where(p => owners.Contains(p.Id))
            .ToList();

        Assert.NotEmpty(children);
    }

    [Fact]
    public void A_copy_that_was_already_running_is_not_in_scope()
    {
        // The defect the first real browser run exposed: capturing Chrome swept in the
        // Chrome the user already had open, because the scope included anything running
        // the same executable. Twenty seconds of a single page load came to 40 MB.
        var earlier = Spawn();

        // Far enough apart that the two start times cannot be confused.
        Thread.Sleep(1200);

        var launched = Spawn();

        var owners = new ProcessTreeReader().DescendantsOf(launched.Id, Cmd);

        Assert.Contains(launched.Id, owners);
        Assert.DoesNotContain(earlier.Id, owners);
    }

    [Fact]
    public void A_copy_started_afterwards_is_in_scope()
    {
        // The rule the start-time bound must not break. A browser re-parents its helpers,
        // so a process that appears after the launch and runs the same binary is almost
        // certainly part of the session even when the tree no longer connects it.
        var launched = Spawn();

        Thread.Sleep(1200);

        var later = Spawn();

        var owners = new ProcessTreeReader().DescendantsOf(launched.Id, Cmd);

        Assert.Contains(later.Id, owners);
    }

    [Fact]
    public void The_idle_and_system_processes_are_never_in_scope()
    {
        // A stale parent link to either would pull the whole machine into the capture.
        var owners = new ProcessTreeReader().DescendantsOf(Environment.ProcessId, null);

        Assert.DoesNotContain(0, owners);
        Assert.DoesNotContain(4, owners);
    }

    [Fact]
    public void An_unknown_process_id_yields_only_itself()
    {
        // Reached when the launched application exits before the first scope refresh.
        // It must not widen to everything whose recorded parent happens to be gone.
        var owners = new ProcessTreeReader().DescendantsOf(0x7FFFFFF0, null);

        Assert.Equal([0x7FFFFFF0], owners);
    }

    public void Dispose()
    {
        foreach (var process in _started)
        {
            try
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit(5000);
            }
            catch (Exception)
            {
                // Already gone, which is where we wanted it.
            }

            process.Dispose();
        }
    }
}
