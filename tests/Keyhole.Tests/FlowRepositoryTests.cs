using System.Net;
using Keyhole.Core.Monitoring;
using Keyhole.Core.Storage;
using Microsoft.Data.Sqlite;

namespace Keyhole.Tests;

public class FlowRepositoryTests : IDisposable
{
    private readonly string _databaseFile =
        Path.Combine(Path.GetTempPath(), $"keyhole-flows-{Guid.NewGuid():n}.sqlite");

    private readonly KeyholeDatabase _database;
    private readonly FlowRepository _repository;

    public FlowRepositoryTests()
    {
        _database = new KeyholeDatabase(_databaseFile);
        new MigrationRunner(_database).Migrate();
        _repository = new FlowRepository(_database);
    }

    private static TrackedFlow Flow(
        int pid = 100,
        string path = @"C:\app.exe",
        string remote = "93.184.216.34",
        int localPort = 50000,
        string? hostname = null,
        DateTimeOffset? ended = null) => new()
        {
            Key = new ConnectionKey(TransportProtocol.Tcp, "192.168.1.10", localPort, remote, 443),
            Connection = new NetworkConnection
            {
                ProcessId = pid,
                Protocol = TransportProtocol.Tcp,
                LocalAddress = IPAddress.Parse("192.168.1.10"),
                LocalPort = localPort,
                RemoteAddress = IPAddress.Parse(remote),
                RemotePort = 443,
                State = TcpConnectionState.Established,
            },
            Process = new ProcessIdentity
            {
                ProcessId = pid,
                ExecutablePath = path,
                DisplayName = Path.GetFileNameWithoutExtension(path),
                Publisher = "Test Publisher",
                Signature = SignatureStatus.Valid,
            },
            StartedUtc = DateTimeOffset.UtcNow,
            LastSeenUtc = DateTimeOffset.UtcNow,
            EndedUtc = ended,
            RemoteHostname = hostname,
        };

    [Fact]
    public void Records_an_opened_flow()
    {
        _repository.RecordSample(new SampleResult([Flow()], [], 1));

        Assert.Equal(1, _repository.CountFlows());
    }

    [Fact]
    public void Repeated_samples_reuse_one_process_row()
    {
        // The regression this guards: SQLite treats NULLs as distinct in a UNIQUE
        // constraint, so an unhashed process row never conflicted with itself and
        // every sample inserted a duplicate.
        for (var i = 0; i < 10; i++)
        {
            _repository.RecordSample(new SampleResult([Flow(localPort: 50000 + i)], [], 1));
        }

        Assert.Equal(1, CountProcesses());
        Assert.Equal(10, _repository.CountFlows());
    }

    [Fact]
    public void Different_executables_get_separate_process_rows()
    {
        _repository.RecordSample(new SampleResult(
            [Flow(path: @"C:\one.exe"), Flow(path: @"C:\two.exe", localPort: 50001)], [], 2));

        Assert.Equal(2, CountProcesses());
    }

    [Fact]
    public void Process_without_a_readable_path_still_gets_one_row()
    {
        var opaque = Flow() with
        {
            Process = new ProcessIdentity
            {
                ProcessId = 4,
                ExecutablePath = null,
                DisplayName = "RpcSs (service)",
                Signature = SignatureStatus.Unknown,
            },
        };

        _repository.RecordSample(new SampleResult([opaque], [], 1));
        _repository.RecordSample(new SampleResult([opaque with { Key = opaque.Key with { LocalPort = 50001 } }], [], 1));

        // Unelevated, most system processes have no readable path. They must not
        // accumulate a new row per sample.
        Assert.Equal(1, CountProcesses());
    }

    [Fact]
    public void Closing_a_flow_sets_its_end_time()
    {
        var flow = Flow();
        _repository.RecordSample(new SampleResult([flow], [], 1));

        var ended = flow with { EndedUtc = DateTimeOffset.UtcNow, BytesSent = 1234, BytesReceived = 5678 };
        _repository.RecordSample(new SampleResult([], [ended], 0));

        using var connection = _database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT ended_utc, bytes_sent, bytes_received FROM flows;";
        using var reader = command.ExecuteReader();

        Assert.True(reader.Read());
        Assert.False(reader.IsDBNull(0));
        Assert.Equal(1234, reader.GetInt64(1));
        Assert.Equal(5678, reader.GetInt64(2));
    }

    [Fact]
    public void Closing_affects_only_the_most_recent_matching_flow()
    {
        // The same endpoints can be reused over time. Closing every matching row
        // would rewrite history that already ended.
        var first = Flow();
        _repository.RecordSample(new SampleResult([first], [], 1));
        _repository.RecordSample(new SampleResult([], [first with { EndedUtc = DateTimeOffset.UtcNow }], 0));

        var second = Flow() with { StartedUtc = DateTimeOffset.UtcNow.AddSeconds(5) };
        _repository.RecordSample(new SampleResult([second], [], 1));

        Assert.Equal(1, CountOpenFlows());

        _repository.RecordSample(new SampleResult([], [second with { EndedUtc = DateTimeOffset.UtcNow }], 0));
        Assert.Equal(0, CountOpenFlows());
        Assert.Equal(2, _repository.CountFlows());
    }

    [Fact]
    public void Hostname_learned_late_is_saved_on_close()
    {
        var flow = Flow(hostname: null);
        _repository.RecordSample(new SampleResult([flow], [], 1));

        _repository.RecordSample(new SampleResult(
            [], [flow with { EndedUtc = DateTimeOffset.UtcNow, RemoteHostname = "example.test" }], 0));

        Assert.Equal("example.test", ReadHostname());
    }

    [Fact]
    public void Closing_without_a_hostname_does_not_erase_a_known_one()
    {
        var flow = Flow(hostname: "example.test");
        _repository.RecordSample(new SampleResult([flow], [], 1));

        _repository.RecordSample(new SampleResult(
            [], [flow with { EndedUtc = DateTimeOffset.UtcNow, RemoteHostname = null }], 0));

        Assert.Equal("example.test", ReadHostname());
    }

    [Fact]
    public void Byte_totals_for_open_flows_reach_the_database()
    {
        // The regression this guards: totals were written only when a flow closed, so a
        // connection still open when the service stopped lost its traffic from history.
        // On a real machine this meant 16 of 16 TCP flows recorded as zero bytes.
        var flow = Flow();
        _repository.RecordSample(new SampleResult([flow], [], 1));

        Assert.Equal(0, ReadBytes().sent);

        _repository.UpdateActiveBytes([flow with { BytesSent = 4096, BytesReceived = 8192 }]);

        var (sent, received) = ReadBytes();
        Assert.Equal(4096, sent);
        Assert.Equal(8192, received);
    }

    [Fact]
    public void Flushing_updates_the_open_row_rather_than_inserting()
    {
        var flow = Flow();
        _repository.RecordSample(new SampleResult([flow], [], 1));

        _repository.UpdateActiveBytes([flow with { BytesSent = 100 }]);
        _repository.UpdateActiveBytes([flow with { BytesSent = 900 }]);

        Assert.Equal(1, _repository.CountFlows());
        Assert.Equal(900, ReadBytes().sent);
    }

    [Fact]
    public void Flushing_leaves_closed_flows_alone()
    {
        var flow = Flow();
        _repository.RecordSample(new SampleResult([flow], [], 1));
        _repository.RecordSample(new SampleResult(
            [], [flow with { EndedUtc = DateTimeOffset.UtcNow, BytesSent = 777 }], 0));

        // A closed row holds its final figures; a stale in-memory copy must not revise them.
        _repository.UpdateActiveBytes([flow with { BytesSent = 1 }]);

        Assert.Equal(777, ReadBytes().sent);
    }

    [Fact]
    public void Flushing_skips_flows_with_nothing_to_report()
    {
        var flow = Flow();
        _repository.RecordSample(new SampleResult([flow], [], 1));

        // Most flows carry no bytes at all without ETW; writing them back every interval
        // would be pure disk traffic.
        Assert.Equal(0, _repository.UpdateActiveBytes([flow]));
        Assert.Equal(0, _repository.UpdateActiveBytes([]));
    }

    [Fact]
    public void Flushed_totals_survive_the_flow_being_orphaned()
    {
        var flow = Flow();
        _repository.RecordSample(new SampleResult([flow], [], 1));
        _repository.UpdateActiveBytes([flow with { BytesSent = 5000, BytesReceived = 6000 }]);

        // Simulates the service being stopped and started again.
        _repository.CloseOrphanedFlows();

        var (sent, received) = ReadBytes();
        Assert.Equal(5000, sent);
        Assert.Equal(6000, received);
    }

    [Fact]
    public void Orphaned_flows_are_closed_on_restart()
    {
        var a = Flow(localPort: 50000);
        var b = Flow(localPort: 50001);
        _repository.RecordSample(new SampleResult([a, b], [], 2));

        // Simulates the service stopping with connections still live.
        Assert.Equal(2, CountOpenFlows());

        var closed = _repository.CloseOrphanedFlows();

        // Left alone, these would read as active forever in the history view.
        Assert.Equal(2, closed);
        Assert.Equal(0, CountOpenFlows());
    }

    [Fact]
    public void Orphaned_flows_are_dated_to_when_they_were_last_seen()
    {
        var lastSeen = DateTimeOffset.UtcNow.AddMinutes(-17);
        var flow = Flow() with { LastSeenUtc = lastSeen };
        _repository.RecordSample(new SampleResult([flow], [], 1));

        _repository.CloseOrphanedFlows();

        using var connection = _database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT ended_utc, last_active_utc FROM flows LIMIT 1;";
        using var reader = command.ExecuteReader();

        Assert.True(reader.Read());

        // The real end time is unknown, so claiming "now" would invent activity that
        // never happened. Last observed is the honest answer.
        Assert.Equal(reader.GetString(1), reader.GetString(0));
    }

    [Fact]
    public void Closing_orphans_leaves_already_closed_flows_alone()
    {
        var flow = Flow();
        _repository.RecordSample(new SampleResult([flow], [], 1));

        var endedAt = DateTimeOffset.UtcNow.AddMinutes(-5);
        _repository.RecordSample(new SampleResult([], [flow with { EndedUtc = endedAt }], 0));

        var before = ReadEndedUtc();
        Assert.Equal(0, _repository.CloseOrphanedFlows());
        Assert.Equal(before, ReadEndedUtc());
    }

    [Fact]
    public void Empty_sample_writes_nothing()
    {
        _repository.RecordSample(new SampleResult([], [], 0));

        Assert.Equal(0, _repository.CountFlows());
    }

    [Fact]
    public void Pruning_removes_only_old_flows()
    {
        var old = Flow(localPort: 50000) with
        {
            StartedUtc = DateTimeOffset.UtcNow.AddDays(-40),
            LastSeenUtc = DateTimeOffset.UtcNow.AddDays(-40),
        };

        _repository.RecordSample(new SampleResult([old, Flow(localPort: 50001)], [], 2));
        Assert.Equal(2, _repository.CountFlows());

        var removed = _repository.PruneOlderThan(TimeSpan.FromDays(30));

        Assert.Equal(1, removed);
        Assert.Equal(1, _repository.CountFlows());
    }

    private long CountProcesses() => Scalar("SELECT COUNT(*) FROM processes;");

    private long CountOpenFlows() => Scalar("SELECT COUNT(*) FROM flows WHERE ended_utc IS NULL;");

    private long Scalar(string sql)
    {
        using var connection = _database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        return Convert.ToInt64(command.ExecuteScalar());
    }

    private (long sent, long received) ReadBytes()
    {
        using var connection = _database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT bytes_sent, bytes_received FROM flows LIMIT 1;";
        using var reader = command.ExecuteReader();
        return reader.Read() ? (reader.GetInt64(0), reader.GetInt64(1)) : (0, 0);
    }

    private string? ReadEndedUtc()
    {
        using var connection = _database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT ended_utc FROM flows LIMIT 1;";
        var value = command.ExecuteScalar();
        return value == DBNull.Value ? null : (string?)value;
    }

    private string? ReadHostname()
    {
        using var connection = _database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT remote_hostname FROM flows LIMIT 1;";
        var value = command.ExecuteScalar();
        return value == DBNull.Value ? null : (string?)value;
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();

        foreach (var suffix in new[] { "", "-wal", "-shm" })
        {
            try
            {
                File.Delete(_databaseFile + suffix);
            }
            catch (IOException)
            {
                // A leaked handle in a failing test must not mask the real failure.
            }
        }
    }
}
