using System.Runtime.InteropServices;

namespace Keyhole.Native.Interop;

/// <summary>
/// advapi32 service control manager queries, used to name the services inside svchost.
/// </summary>
internal static partial class ServiceApi
{
    internal const uint SC_MANAGER_ENUMERATE_SERVICE = 0x0004;
    internal const uint SC_MANAGER_CONNECT = 0x0001;

    internal const uint SERVICE_WIN32 = 0x00000030;
    internal const uint SERVICE_STATE_ALL = 0x00000003;

    /// <summary>SC_ENUM_PROCESS_INFO — the only enum level that reports each service's PID.</summary>
    internal const int SC_ENUM_PROCESS_INFO = 0;

    internal const int ERROR_MORE_DATA = 234;

    /// <summary>Enough to read one service's state without the right to control it.</summary>
    internal const uint SERVICE_QUERY_STATUS = 0x0004;

    /// <summary>SERVICE_STATUS.dwCurrentState values Keyhole distinguishes.</summary>
    internal const uint SERVICE_STOPPED = 0x00000001;
    internal const uint SERVICE_START_PENDING = 0x00000002;
    internal const uint SERVICE_STOP_PENDING = 0x00000003;
    internal const uint SERVICE_RUNNING = 0x00000004;

    [LibraryImport("advapi32.dll", EntryPoint = "OpenSCManagerW", SetLastError = true,
        StringMarshalling = StringMarshalling.Utf16)]
    internal static partial IntPtr OpenSCManager(string? machineName, string? databaseName, uint desiredAccess);

    [LibraryImport("advapi32.dll", EntryPoint = "OpenServiceW", SetLastError = true,
        StringMarshalling = StringMarshalling.Utf16)]
    internal static partial IntPtr OpenService(IntPtr serviceManager, string serviceName, uint desiredAccess);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool QueryServiceStatus(IntPtr service, out SERVICE_STATUS status);

    [StructLayout(LayoutKind.Sequential)]
    internal struct SERVICE_STATUS
    {
        public uint dwServiceType;
        public uint dwCurrentState;
        public uint dwControlsAccepted;
        public uint dwWin32ExitCode;
        public uint dwServiceSpecificExitCode;
        public uint dwCheckPoint;
        public uint dwWaitHint;
    }

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CloseServiceHandle(IntPtr handle);

    [LibraryImport("advapi32.dll", EntryPoint = "EnumServicesStatusExW", SetLastError = true,
        StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool EnumServicesStatusEx(
        IntPtr serviceManager,
        int infoLevel,
        uint serviceType,
        uint serviceState,
        IntPtr services,
        uint bufferSize,
        out uint bytesNeeded,
        out uint servicesReturned,
        ref uint resumeHandle,
        string? groupName);

    [StructLayout(LayoutKind.Sequential)]
    internal struct ENUM_SERVICE_STATUS_PROCESS
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string lpServiceName;
        [MarshalAs(UnmanagedType.LPWStr)] public string lpDisplayName;
        public SERVICE_STATUS_PROCESS ServiceStatusProcess;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SERVICE_STATUS_PROCESS
    {
        public uint dwServiceType;
        public uint dwCurrentState;
        public uint dwControlsAccepted;
        public uint dwWin32ExitCode;
        public uint dwServiceSpecificExitCode;
        public uint dwCheckPoint;
        public uint dwWaitHint;
        public uint dwProcessId;
        public uint dwServiceFlags;
    }
}
