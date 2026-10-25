using System.Runtime.InteropServices;

namespace Keyhole.Native.Interop;

/// <summary>
/// iphlpapi.dll declarations for enumerating sockets with their owning process.
/// These calls succeed without elevation, which is what lets Keyhole show the app list
/// before the service is installed.
/// </summary>
internal static partial class IpHelperApi
{
    internal const int NO_ERROR = 0;
    internal const int ERROR_INSUFFICIENT_BUFFER = 122;

    internal const int AF_INET = 2;
    internal const int AF_INET6 = 23;

    /// <summary>TCP_TABLE_OWNER_PID_ALL — every connection, with its owning PID.</summary>
    internal const int TCP_TABLE_OWNER_PID_ALL = 5;

    /// <summary>UDP_TABLE_OWNER_PID — every UDP endpoint, with its owning PID.</summary>
    internal const int UDP_TABLE_OWNER_PID = 1;

    [LibraryImport("iphlpapi.dll")]
    internal static partial uint GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int pdwSize,
        [MarshalAs(UnmanagedType.Bool)] bool bOrder,
        int ulAf,
        int tableClass,
        int reserved);

    [LibraryImport("iphlpapi.dll")]
    internal static partial uint GetExtendedUdpTable(
        IntPtr pUdpTable,
        ref int pdwSize,
        [MarshalAs(UnmanagedType.Bool)] bool bOrder,
        int ulAf,
        int tableClass,
        int reserved);

    // Layouts below mirror the MIB_* structs in iphlpapi.h. Field order is load-bearing.

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIB_TCPROW_OWNER_PID
    {
        public uint state;
        public uint localAddr;
        // Ports are big-endian in a 4-byte field; only the low two bytes carry the value.
        public uint localPort;
        public uint remoteAddr;
        public uint remotePort;
        public uint owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIB_TCP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] localAddr;
        public uint localScopeId;
        public uint localPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] remoteAddr;
        public uint remoteScopeId;
        public uint remotePort;
        public uint state;
        public uint owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIB_UDPROW_OWNER_PID
    {
        public uint localAddr;
        public uint localPort;
        public uint owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIB_UDP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] localAddr;
        public uint localScopeId;
        public uint localPort;
        public uint owningPid;
    }
}
