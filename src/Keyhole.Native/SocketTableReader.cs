using System.Net;
using System.Runtime.InteropServices;
using Keyhole.Core.Monitoring;
using Keyhole.Native.Interop;

namespace Keyhole.Native;

/// <summary>
/// Reads the OS socket tables and returns every connection with its owning process.
/// This is a point-in-time snapshot: a connection that opens and closes between two
/// reads is invisible here. ETW fills that gap for byte counts; for the app list,
/// sampling is enough and costs far less.
/// </summary>
public sealed class SocketTableReader : ISocketTableReader
{
    public IReadOnlyList<NetworkConnection> ReadAll()
    {
        var connections = new List<NetworkConnection>(256);

        connections.AddRange(ReadTcp4());
        connections.AddRange(ReadTcp6());
        connections.AddRange(ReadUdp4());
        connections.AddRange(ReadUdp6());

        return connections;
    }

    private static IEnumerable<NetworkConnection> ReadTcp4() =>
        ReadTable(
            IpHelperApi.AF_INET,
            IpHelperApi.TCP_TABLE_OWNER_PID_ALL,
            isTcp: true,
            static (IpHelperApi.MIB_TCPROW_OWNER_PID row) => new NetworkConnection
            {
                ProcessId = (int)row.owningPid,
                Protocol = TransportProtocol.Tcp,
                LocalAddress = new IPAddress(row.localAddr),
                LocalPort = DecodePort(row.localPort),
                RemoteAddress = new IPAddress(row.remoteAddr),
                RemotePort = DecodePort(row.remotePort),
                State = (TcpConnectionState)row.state,
            });

    private static IEnumerable<NetworkConnection> ReadTcp6() =>
        ReadTable(
            IpHelperApi.AF_INET6,
            IpHelperApi.TCP_TABLE_OWNER_PID_ALL,
            isTcp: true,
            static (IpHelperApi.MIB_TCP6ROW_OWNER_PID row) => new NetworkConnection
            {
                ProcessId = (int)row.owningPid,
                Protocol = TransportProtocol.Tcp,
                LocalAddress = new IPAddress(row.localAddr, row.localScopeId),
                LocalPort = DecodePort(row.localPort),
                RemoteAddress = new IPAddress(row.remoteAddr, row.remoteScopeId),
                RemotePort = DecodePort(row.remotePort),
                State = (TcpConnectionState)row.state,
            });

    private static IEnumerable<NetworkConnection> ReadUdp4() =>
        ReadTable(
            IpHelperApi.AF_INET,
            IpHelperApi.UDP_TABLE_OWNER_PID,
            isTcp: false,
            static (IpHelperApi.MIB_UDPROW_OWNER_PID row) => new NetworkConnection
            {
                ProcessId = (int)row.owningPid,
                Protocol = TransportProtocol.Udp,
                LocalAddress = new IPAddress(row.localAddr),
                LocalPort = DecodePort(row.localPort),
                // UDP is connectionless: the table has no peer to report.
                RemoteAddress = IPAddress.Any,
                RemotePort = 0,
                State = TcpConnectionState.None,
            });

    private static IEnumerable<NetworkConnection> ReadUdp6() =>
        ReadTable(
            IpHelperApi.AF_INET6,
            IpHelperApi.UDP_TABLE_OWNER_PID,
            isTcp: false,
            static (IpHelperApi.MIB_UDP6ROW_OWNER_PID row) => new NetworkConnection
            {
                ProcessId = (int)row.owningPid,
                Protocol = TransportProtocol.Udp,
                LocalAddress = new IPAddress(row.localAddr, row.localScopeId),
                LocalPort = DecodePort(row.localPort),
                RemoteAddress = IPAddress.IPv6Any,
                RemotePort = 0,
                State = TcpConnectionState.None,
            });

    /// <summary>
    /// Allocates, calls the API and projects each row. The table layout is a DWORD count
    /// followed by a packed array of fixed-size rows.
    /// </summary>
    private static List<NetworkConnection> ReadTable<TRow>(
        int addressFamily,
        int tableClass,
        bool isTcp,
        Func<TRow, NetworkConnection> project)
        where TRow : struct
    {
        var size = 0;
        var fetch = isTcp
            ? (IntPtr buffer, ref int length) =>
                IpHelperApi.GetExtendedTcpTable(buffer, ref length, false, addressFamily, tableClass, 0)
            : (FetchTable)((IntPtr buffer, ref int length) =>
                IpHelperApi.GetExtendedUdpTable(buffer, ref length, false, addressFamily, tableClass, 0));

        // First call sizes the buffer. The table can grow between the two calls, so retry
        // rather than assuming the reported size still holds.
        var result = fetch(IntPtr.Zero, ref size);
        if (result != IpHelperApi.ERROR_INSUFFICIENT_BUFFER && result != IpHelperApi.NO_ERROR)
        {
            throw new InvalidOperationException(
                $"Socket table query failed for family {addressFamily} with code {result}.");
        }

        for (var attempt = 0; attempt < 5; attempt++)
        {
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                result = fetch(buffer, ref size);

                if (result == IpHelperApi.ERROR_INSUFFICIENT_BUFFER)
                {
                    // size now holds the larger requirement; loop and allocate again.
                    continue;
                }

                if (result != IpHelperApi.NO_ERROR)
                {
                    throw new InvalidOperationException(
                        $"Socket table query failed for family {addressFamily} with code {result}.");
                }

                return ProjectRows(buffer, project);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        throw new InvalidOperationException(
            $"Socket table for family {addressFamily} kept growing across 5 attempts.");
    }

    private static List<NetworkConnection> ProjectRows<TRow>(IntPtr buffer, Func<TRow, NetworkConnection> project)
        where TRow : struct
    {
        var rowCount = Marshal.ReadInt32(buffer);
        var rows = new List<NetworkConnection>(rowCount);

        var rowSize = Marshal.SizeOf<TRow>();
        var cursor = buffer + sizeof(int);

        for (var i = 0; i < rowCount; i++)
        {
            var row = Marshal.PtrToStructure<TRow>(cursor);
            rows.Add(project(row));
            cursor += rowSize;
        }

        return rows;
    }

    /// <summary>
    /// Ports arrive in a DWORD holding a big-endian uint16. Taking the low two bytes and
    /// swapping them is the documented decoding; reading the DWORD directly yields garbage
    /// like 20480 instead of 80.
    /// </summary>
    private static int DecodePort(uint raw)
    {
        var low = (byte)(raw & 0xFF);
        var high = (byte)((raw >> 8) & 0xFF);
        return (low << 8) | high;
    }

    private delegate uint FetchTable(IntPtr buffer, ref int length);
}
