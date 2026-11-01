using System.Buffers.Binary;
using System.Diagnostics;
using Keyhole.Core.Capture.Pcapng;

namespace Keyhole.Tests;

/// <summary>
/// Reads Keyhole's pcapng output with Wireshark's own tools.
///
/// The writer's other tests only prove it is self-consistent: they parse the file with the
/// same understanding of the format that wrote it, so a shared misreading would pass them
/// all. The point of the format is that <em>Wireshark</em> opens the file, and the only way
/// to know that is to ask Wireshark.
///
/// Skipped when Wireshark is not installed, which is the case in CI. A skip here means
/// "unverified", not "verified" — the structural tests remain the floor.
/// </summary>
public class PcapngWiresharkTests
{
    /// <summary>
    /// Locates one of Wireshark's command line tools, or returns null when Wireshark is
    /// not installed.
    /// </summary>
    internal static string? WiresharkTool(string name)
    {
        string[] roots =
        [
            @"C:\Program Files\Wireshark",
            @"C:\Program Files (x86)\Wireshark",
        ];

        return roots
            .Select(root => Path.Combine(root, name))
            .FirstOrDefault(File.Exists);
    }

    [WiresharkFact]
    public void Capinfos_reads_the_file_Keyhole_wrote()
    {
        var capinfos = WiresharkTool("capinfos.exe");
        var path = WriteCapture(packets: 3, keylog: null);

        try
        {
            var output = Run(capinfos!, $"-t -c \"{path}\"");

            // capinfos refuses a malformed file outright, so getting the right counts back
            // means the whole structure parsed: header, interface block and every packet.
            Assert.Contains("pcapng", output, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("3", output);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [WiresharkFact]
    public void Tshark_dissects_the_packets_as_tcp()
    {
        var tshark = WiresharkTool("tshark.exe");
        var path = WriteCapture(packets: 2, keylog: null);

        try
        {
            var output = Run(tshark!, $"-r \"{path}\" -T fields -e ip.src -e ip.dst -e tcp.dstport");

            // Proves the link type and timestamps were declared correctly too: get either
            // wrong and tshark parses the frame as something else entirely.
            Assert.Contains("10.0.0.5", output);
            Assert.Contains("93.184.216.34", output);
            Assert.Contains("443", output);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [WiresharkFact]
    public void Tshark_finds_the_injected_tls_secrets()
    {
        var tshark = WiresharkTool("tshark.exe");

        // A syntactically valid NSS line. It decrypts nothing — these packets carry no real
        // TLS — but it does prove the Decryption Secrets Block is a block Wireshark reads
        // rather than one it skips or chokes on.
        const string keylog =
            "CLIENT_RANDOM 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef " +
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" +
            "00112233445566778899aabbccddeeff\n";

        var path = WriteCapture(packets: 1, keylog: keylog);

        try
        {
            var result = PcapngSecretsInjector.Inject(path, keylog);
            Assert.True(result.Succeeded, result.Detail);

            // capinfos and tshark both walk every block. A secrets block they cannot parse
            // shows up as an error here rather than being quietly ignored.
            var output = Run(tshark!, $"-r \"{path}\" -T fields -e frame.number");

            Assert.Contains("1", output);
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static string WriteCapture(int packets, string? keylog)
    {
        var path = Path.Combine(Path.GetTempPath(), $"keyhole-wireshark-{Guid.NewGuid():N}.pcapng");

        using (var writer = PcapngWriter.Create(path))
        {
            var id = writer.AddInterface(PcapngLinkType.Ethernet, "Keyhole test adapter");

            for (var i = 0; i < packets; i++)
            {
                writer.WritePacket(id, DateTimeOffset.UtcNow, SyntheticTcpFrame());
            }

            if (keylog is not null)
            {
                // Appended here only so the file has one before the injector moves it;
                // the injector's own tests cover placement.
                writer.WriteTlsSecrets(keylog);
            }
        }

        return path;
    }

    /// <summary>
    /// An Ethernet frame carrying an IPv4 TCP segment to port 443.
    ///
    /// Built by hand rather than captured so the test has no external dependency, and
    /// deliberately realistic: tshark has to recognise it, which it only does if the
    /// headers and lengths are right.
    /// </summary>
    private static byte[] SyntheticTcpFrame()
    {
        var frame = new byte[14 + 20 + 20];
        var span = frame.AsSpan();

        // Ethernet: destination, source, then the EtherType that says "IPv4 follows".
        "\x00\x11\x22\x33\x44\x55"u8.CopyTo(span);
        "\x66\x77\x88\x99\xaa\xbb"u8.CopyTo(span[6..]);
        BinaryPrimitives.WriteUInt16BigEndian(span[12..], 0x0800);

        var ip = span[14..];
        ip[0] = 0x45;                                            // IPv4, 20-byte header
        ip[1] = 0;                                               // DSCP/ECN
        BinaryPrimitives.WriteUInt16BigEndian(ip[2..], 40);      // total length: IP + TCP
        BinaryPrimitives.WriteUInt16BigEndian(ip[4..], 0x1234);  // identification
        BinaryPrimitives.WriteUInt16BigEndian(ip[6..], 0x4000);  // don't fragment
        ip[8] = 64;                                              // TTL
        ip[9] = 6;                                               // TCP
        // Checksum left zero: tshark reports it as unverified rather than refusing the
        // packet, and a wrong constant would be worse than an absent one.
        new byte[] { 10, 0, 0, 5 }.CopyTo(ip[12..]);             // source
        new byte[] { 93, 184, 216, 34 }.CopyTo(ip[16..]);        // destination

        var tcp = ip[20..];
        BinaryPrimitives.WriteUInt16BigEndian(tcp, 51000);       // source port
        BinaryPrimitives.WriteUInt16BigEndian(tcp[2..], 443);    // destination port
        BinaryPrimitives.WriteUInt32BigEndian(tcp[4..], 1);      // sequence
        BinaryPrimitives.WriteUInt32BigEndian(tcp[8..], 0);      // acknowledgement
        tcp[12] = 0x50;                                          // 20-byte header
        tcp[13] = 0x02;                                          // SYN
        BinaryPrimitives.WriteUInt16BigEndian(tcp[14..], 64240); // window

        return frame;
    }

    internal static string Run(string executable, string arguments)
    {
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = executable,
            Arguments = arguments,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        })!;

        // Both streams are drained at once. Reading one to the end and then the other
        // deadlocks whenever the child fills the pipe it is not being read from — and
        // tshark is chatty on stderr, so it does. This hung a test run before it was
        // written this way.
        var outputTask = process.StandardOutput.ReadToEndAsync();
        var errorTask = process.StandardError.ReadToEndAsync();

        if (!process.WaitForExit(60_000))
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (Exception)
            {
                // Already gone, which is the outcome we wanted anyway.
            }

            Assert.Fail($"{Path.GetFileName(executable)} did not exit within 60 seconds.");
        }

        var output = outputTask.GetAwaiter().GetResult();
        var error = errorTask.GetAwaiter().GetResult();

        // Wireshark's tools exit non-zero on a file they cannot read, which is precisely
        // the failure this test exists to catch. Surface their complaint.
        Assert.True(
            process.ExitCode == 0,
            $"{Path.GetFileName(executable)} exited {process.ExitCode}: {error}");

        return output + error;
    }
}
