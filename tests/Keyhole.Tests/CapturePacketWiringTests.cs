using Keyhole.Core.Capture;
using Keyhole.Core.Capture.Recording;
using Keyhole.Core.Storage;

namespace Keyhole.Tests;

/// <summary>
/// How a capture session and its packet recording are joined.
///
/// The thing worth protecting here is that the two are separable. Keylog-only sessions
/// were the whole of M5, and a machine without Npcap still only gets those — so packet
/// recording failing to start must never fail the launch, and the session must say which
/// of the two it got rather than leaving the user to guess from an empty column.
/// </summary>
public class CapturePacketWiringTests : IDisposable
{
    private readonly string _databaseFile =
        Path.Combine(Path.GetTempPath(), $"keyhole-wiring-{Guid.NewGuid():n}.sqlite");

    private readonly string _captureRoot =
        Path.Combine(Path.GetTempPath(), $"keyhole-wiring-captures-{Guid.NewGuid():n}");

    private KeyholeDatabase? _database;

    private static string Cmd => Path.Combine(Environment.SystemDirectory, "cmd.exe");

    /// <summary>
    /// Arguments that keep cmd.exe alive for a few seconds.
    ///
    /// "/c exit" returns before the test's next line runs, and the exit handler then stops
    /// the recording from under it — which made these tests pass alone and fail under
    /// load. Keeping the process alive is what makes them test the thing they describe
    /// rather than a race.
    /// </summary>
    private const string StaysAlive = "/c ping -n 6 127.0.0.1";

    /// <summary>
    /// Processes these tests launched.
    ///
    /// Tracked because stopping a capture deliberately leaves the application running —
    /// the user started it to use it — which is right in production and litter in a test.
    /// </summary>
    private readonly List<int> _launched = [];

    private Keyhole.Core.Capture.CaptureSession Launch(CaptureService service)
    {
        var session = service.Start(Cmd, StaysAlive);

        if (session.ProcessId is { } pid)
        {
            _launched.Add(pid);
        }

        return session;
    }

    private CaptureService Build(IPacketDeviceFactory? devices)
    {
        _database = new KeyholeDatabase(_databaseFile);
        new MigrationRunner(_database).Migrate();

        return new CaptureService(
            new SessionRepository(_database),
            logger: null,
            captureRoot: _captureRoot,
            packetDevices: devices,
            sockets: devices is null ? null : new FakeSockets([]),
            processTree: new FakeTree([]));
    }

    [Fact]
    public void A_session_records_packets_when_an_adapter_is_available()
    {
        var service = Build(new SingleDeviceFactory(new FakeDevice()));

        var session = Launch(service);

        Assert.NotNull(session.PcapFile);
        Assert.Equal(CaptureService.PcapFileName, Path.GetFileName(session.PcapFile));

        // The path is in the session row, not only in memory, so the UI still finds the
        // capture after the service restarts.
        var stored = service.ListSessions().Single(s => s.Id == session.Id);
        Assert.Equal(session.PcapFile, stored.PcapFile);

        service.Stop(session.Id);
        Assert.True(File.Exists(session.PcapFile));
    }

    [Fact]
    public void Without_npcap_the_session_still_starts_and_explains_itself()
    {
        var service = Build(new UnavailableDevices("Npcap is not installed."));

        var session = Launch(service);

        // This is the behaviour M5 shipped with, and it must survive M8: the keylog is the
        // point, and packets are an addition.
        Assert.NotNull(session.KeylogFile);
        Assert.Null(session.PcapFile);

        Assert.Equal("Npcap is not installed.", service.GetRecordingIssue(session.Id));

        // And it survives the session ending. The UI shows a note against finished
        // captures too, and this is exactly the note a finished keylog-only session needs.
        service.Stop(session.Id);
        Assert.Equal("Npcap is not installed.", service.GetRecordingIssue(session.Id));
    }

    [Fact]
    public void A_service_with_no_capture_backend_behaves_as_it_did_before()
    {
        // Nothing wired up at all, which is how the unit tests and any build without the
        // Npcap binding run.
        var service = Build(devices: null);

        Assert.False(service.CanRecordPackets);

        var session = Launch(service);

        Assert.Null(session.PcapFile);
        Assert.Null(service.GetRecordingIssue(session.Id));
    }

    [Fact]
    public void Stopping_a_session_writes_the_keylog_into_the_capture()
    {
        var service = Build(new SingleDeviceFactory(new FakeDevice()));

        var session = Launch(service);

        // Stand in for what an NSS application would have written by now.
        File.WriteAllText(session.KeylogFile, "CLIENT_RANDOM aabb ccdd\n");

        service.Stop(session.Id);

        var bytes = File.ReadAllBytes(session.PcapFile!);

        // A Decryption Secrets Block, which is what makes the capture self-contained. Its
        // absence would mean every capture needs its keylog carried alongside by hand —
        // precisely the workflow M8 exists to remove.
        Assert.Contains(0x0000000Au, BlockTypes(bytes));
    }

    [Fact]
    public void The_pcap_size_is_reported_only_when_there_is_a_pcap()
    {
        var service = Build(new UnavailableDevices("No adapter."));

        // Zero for a session with no capture, so the UI can show an em dash rather than
        // "0 B" — which would read as an empty recording rather than none at all.
        Assert.Equal(0, service.GetPcapSize(null));
        Assert.Equal(0, service.GetPcapSize("C:\\nonexistent\\capture.pcapng"));
    }

    private static List<uint> BlockTypes(byte[] bytes)
    {
        var types = new List<uint>();
        var offset = 0;

        while (offset + 8 <= bytes.Length)
        {
            types.Add(System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset)));
            var length = (int)System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(
                bytes.AsSpan(offset + 4));

            Assert.True(length >= 12 && offset + length <= bytes.Length);
            offset += length;
        }

        return types;
    }

    public void Dispose()
    {
        foreach (var pid in _launched)
        {
            try
            {
                System.Diagnostics.Process.GetProcessById(pid).Kill(entireProcessTree: true);
            }
            catch (Exception)
            {
                // Already gone, which is the state we were after.
            }
        }

        // The connection pool keeps the file handle open, so it has to be cleared before
        // the database file can be deleted.
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();

        try
        {
            File.Delete(_databaseFile);

            if (Directory.Exists(_captureRoot))
            {
                Directory.Delete(_captureRoot, recursive: true);
            }
        }
        catch (IOException)
        {
            // Temp files left behind are not worth failing a test over.
        }
    }
}
