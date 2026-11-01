using System.Runtime.InteropServices;
using Keyhole.Core.Capture.Recording;
using Keyhole.Native.Interop;

namespace Keyhole.Native;

/// <summary>
/// Works out which processes make up one launched application.
///
/// A capture scoped to a single process id would record almost nothing from a browser: it
/// hands network work to child processes, and that is where the traffic is. So the scope
/// is the whole tree below the launched process — plus anything running the same
/// executable, because browsers re-parent their helpers and a child whose parent exited
/// drops out of the tree while still doing the application's work.
///
/// That second rule is bounded by start time, and the bound matters. Without it, capturing
/// a browser the user already had open swept their entire existing session into the
/// recording: the first real run produced 40 MB in twenty seconds for a single page load.
/// A process that started before the one Keyhole launched cannot be part of it, so the
/// comparison is both cheap and exact.
/// </summary>
public sealed class ProcessTreeReader : IProcessTreeReader
{
    public HashSet<int> DescendantsOf(int rootProcessId, string? executablePath)
    {
        var processes = Snapshot();
        var startTimes = new StartTimeCache();

        HashSet<int> owners = [rootProcessId];

        // Walk parent links repeatedly rather than once: the snapshot is in no particular
        // order, so a grandchild may be listed before its parent is known to be ours.
        bool grew;
        do
        {
            grew = false;

            foreach (var entry in processes)
            {
                if (owners.Contains(entry.ProcessId) || !owners.Contains(entry.ParentProcessId))
                {
                    continue;
                }

                // Windows does not clear a process's recorded parent when that parent
                // exits, and it reuses process ids. So an unrelated process started after
                // ours died can name our id as its parent and look like our child. A child
                // cannot predate its parent, which is enough to tell the two apart — and
                // without this check a capture can quietly record a stranger's traffic
                // into a file that also holds TLS keys.
                if (!startTimes.StartedAfter(entry.ProcessId, entry.ParentProcessId))
                {
                    continue;
                }

                owners.Add(entry.ProcessId);
                grew = true;
            }
        }
        while (grew);

        if (!string.IsNullOrWhiteSpace(executablePath))
        {
            var name = Path.GetFileName(executablePath);

            foreach (var entry in processes)
            {
                if (!string.Equals(entry.Name, name, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                // Only processes that appeared at or after the launch. A copy of the same
                // browser the user already had running is not part of this capture, and
                // including it records a session nobody asked to record — into a file that
                // also holds the keys to read it.
                //
                // Unreadable times exclude here, the opposite of the tree rule above. This
                // is a safety net over a rule that is already correct, so a hole in it
                // costs some of the target's traffic; being wrong the other way costs a
                // bystander their privacy.
                if (startTimes.StartedAfterOrExclude(entry.ProcessId, rootProcessId))
                {
                    owners.Add(entry.ProcessId);
                }
            }
        }

        // PID 0 is the idle process and PID 4 the kernel; neither owns a socket, and
        // treating either as a tree member would widen the scope for nothing.
        owners.Remove(0);
        owners.Remove(4);

        return owners;
    }

    /// <summary>
    /// Every process on the machine with its parent, or an empty list when the snapshot
    /// cannot be taken.
    /// </summary>
    private static List<ProcessEntry> Snapshot()
    {
        var snapshot = ProcessApi.CreateToolhelp32Snapshot(ProcessApi.TH32CS_SNAPPROCESS, 0);

        // INVALID_HANDLE_VALUE, not null, on failure.
        if (snapshot == IntPtr.Zero || snapshot == new IntPtr(-1))
        {
            return [];
        }

        try
        {
            var entry = new ProcessApi.PROCESSENTRY32
            {
                dwSize = (uint)Marshal.SizeOf<ProcessApi.PROCESSENTRY32>(),
            };

            if (!ProcessApi.Process32First(snapshot, ref entry))
            {
                return [];
            }

            var processes = new List<ProcessEntry>(512);

            do
            {
                processes.Add(new ProcessEntry(
                    (int)entry.th32ProcessID,
                    (int)entry.th32ParentProcessID,
                    entry.ExeFile));
            }
            while (ProcessApi.Process32Next(snapshot, ref entry));

            return processes;
        }
        finally
        {
            ProcessApi.CloseHandle(snapshot);
        }
    }

    /// <summary>
    /// Process start times, read on demand and remembered.
    ///
    /// Only candidates for the tree are ever looked up — a handful per refresh — so this
    /// costs far less than reading start times for every process on the machine.
    /// </summary>
    private sealed class StartTimeCache
    {
        private readonly Dictionary<int, long?> _times = [];

        /// <summary>
        /// Whether <paramref name="childId"/> could really be a child of
        /// <paramref name="parentId"/>, judged by start order.
        ///
        /// Unreadable times mean the pair is accepted. Erring towards including a process
        /// errs towards recording what the user asked for; the alternative silently drops
        /// traffic, which is the harder failure to notice.
        /// </summary>
        public bool StartedAfter(int childId, int parentId)
        {
            var child = Lookup(childId);
            var parent = Lookup(parentId);

            if (child is null || parent is null)
            {
                return true;
            }

            return child.Value >= parent.Value;
        }

        /// <summary>
        /// The same comparison, but an unreadable time excludes rather than includes.
        ///
        /// Used where including the wrong process records someone else's traffic, and
        /// excluding the right one merely records less of the target's. The two rules
        /// genuinely want opposite defaults, so they are separate methods rather than one
        /// with a flag nobody would read correctly at the call site.
        /// </summary>
        public bool StartedAfterOrExclude(int childId, int parentId)
        {
            var child = Lookup(childId);
            var parent = Lookup(parentId);

            return child is not null && parent is not null && child.Value >= parent.Value;
        }

        private long? Lookup(int processId)
        {
            if (_times.TryGetValue(processId, out var cached))
            {
                return cached;
            }

            var time = Read(processId);
            _times[processId] = time;
            return time;
        }

        private static long? Read(int processId)
        {
            using var handle = ProcessApi.OpenProcess(
                ProcessApi.PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)processId);

            if (handle.IsInvalid)
            {
                return null;
            }

            return ProcessApi.GetProcessTimes(handle, out var creation, out _, out _, out _)
                ? creation
                : null;
        }
    }

    private readonly record struct ProcessEntry(int ProcessId, int ParentProcessId, string Name);
}
