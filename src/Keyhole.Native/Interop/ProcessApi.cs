using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Keyhole.Native.Interop;

/// <summary>
/// kernel32 process queries.
/// Deliberately uses PROCESS_QUERY_LIMITED_INFORMATION rather than the full query right:
/// the limited right succeeds against processes running as other users, which is most of
/// what a machine-wide monitor needs to see, and asks for no more than Keyhole uses.
/// </summary>
internal static partial class ProcessApi
{
    internal const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial SafeProcessHandle OpenProcess(
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        uint processId);

    [LibraryImport("kernel32.dll", SetLastError = true, EntryPoint = "QueryFullProcessImageNameW",
        StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool QueryFullProcessImageName(
        SafeProcessHandle process,
        uint flags,
        [Out] char[] exeName,
        ref uint size);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetProcessTimes(
        SafeProcessHandle process,
        out long creationTime,
        out long exitTime,
        out long kernelTime,
        out long userTime);

    internal const uint TH32CS_SNAPPROCESS = 0x00000002;

    /// <summary>
    /// The process list with each entry's parent, which is the only way to reconstruct a
    /// process tree. .NET exposes no parent process id, and the documented alternatives
    /// (NtQueryInformationProcess, WMI) are respectively undocumented-adjacent and slow
    /// enough to notice when polled during a capture.
    /// </summary>
    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);

    [LibraryImport("kernel32.dll", EntryPoint = "Process32FirstW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool Process32First(IntPtr snapshot, ref PROCESSENTRY32 entry);

    [LibraryImport("kernel32.dll", EntryPoint = "Process32NextW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool Process32Next(IntPtr snapshot, ref PROCESSENTRY32 entry);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CloseHandle(IntPtr handle);

    internal const int MAX_PATH = 260;

    /// <summary>
    /// The name buffer is a fixed array rather than a marshalled string: source-generated
    /// P/Invoke does not support ByValTStr, and a blittable struct needs no marshalling at
    /// all — which matters here because this is read for every process on the machine.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct PROCESSENTRY32
    {
        /// <summary>Must be set to the struct's size before the first call, or it fails.</summary>
        public uint dwSize;

        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;

        /// <summary>
        /// The image file name only, never a full path. Enough to recognise a process by
        /// name, which is what the capture scope needs when a path is unreadable.
        /// </summary>
        public fixed char szExeFile[MAX_PATH];

        /// <summary>The image name as a string, stopping at the terminating null.</summary>
        public string ExeFile
        {
            get
            {
                fixed (char* name = szExeFile)
                {
                    return new string(name);
                }
            }
        }
    }
}
