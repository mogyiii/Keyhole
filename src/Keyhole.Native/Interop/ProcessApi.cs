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
}
