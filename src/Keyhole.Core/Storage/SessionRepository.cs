using Keyhole.Core.Capture;
using Microsoft.Data.Sqlite;

namespace Keyhole.Core.Storage;

/// <summary>Stores capture sessions so past captures remain findable after a restart.</summary>
public sealed class SessionRepository(KeyholeDatabase database)
{
    /// <summary>
    /// The columns every read returns, in the order <see cref="Read"/> expects them.
    /// Kept in one place because three queries share it and a column added to one but not
    /// the others would read as the wrong field rather than fail.
    /// </summary>
    private const string Columns =
        "id, executable_path, pid, mode, directory, pcap_file, keylog_file, started_utc, stopped_utc";

    public CaptureSession Create(CaptureSession session)
    {
        using var connection = database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            INSERT INTO sessions (executable_path, pid, mode, directory, pcap_file, keylog_file,
                                  started_utc, stopped_utc)
            VALUES ($path, $pid, $mode, $dir, $pcap, $keylog, $started, NULL)
            RETURNING {Columns};
            """;

        command.Parameters.AddWithValue("$path", session.ExecutablePath);
        command.Parameters.AddWithValue("$pid", (object?)session.ProcessId ?? DBNull.Value);
        command.Parameters.AddWithValue("$mode", session.Mode == CaptureMode.Proxy ? "proxy" : "keylog");
        command.Parameters.AddWithValue("$dir", session.Directory);
        command.Parameters.AddWithValue("$pcap", (object?)session.PcapFile ?? DBNull.Value);
        command.Parameters.AddWithValue("$keylog", session.KeylogFile);
        command.Parameters.AddWithValue("$started", session.StartedUtc.ToString("O"));

        using var reader = command.ExecuteReader();
        reader.Read();
        return Read(reader);
    }

    public IReadOnlyList<CaptureSession> ListAll()
    {
        using var connection = database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            SELECT {Columns}
              FROM sessions
             ORDER BY started_utc DESC;
            """;

        using var reader = command.ExecuteReader();

        var sessions = new List<CaptureSession>();
        while (reader.Read())
        {
            sessions.Add(Read(reader));
        }

        return sessions;
    }

    public CaptureSession? FindById(long id)
    {
        using var connection = database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = $"SELECT {Columns} FROM sessions WHERE id = $id;";
        command.Parameters.AddWithValue("$id", id);

        using var reader = command.ExecuteReader();
        return reader.Read() ? Read(reader) : null;
    }

    /// <summary>
    /// Records where a session's packet capture ended up.
    ///
    /// Written separately from <see cref="Create"/> because recording may fail to start
    /// for reasons only known after the session row exists — no Npcap, no adapter, an
    /// unwritable folder — and a path stored for a file that was never created would send
    /// the UI looking for it.
    /// </summary>
    public void SetPcapFile(long id, string? pcapFile)
    {
        using var connection = database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "UPDATE sessions SET pcap_file = $pcap WHERE id = $id;";
        command.Parameters.AddWithValue("$pcap", (object?)pcapFile ?? DBNull.Value);
        command.Parameters.AddWithValue("$id", id);
        command.ExecuteNonQuery();
    }

    /// <summary>Marks a session finished. Idempotent: the first stop time recorded wins.</summary>
    public void MarkStopped(long id, DateTimeOffset stoppedUtc)
    {
        using var connection = database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText =
            "UPDATE sessions SET stopped_utc = $stopped WHERE id = $id AND stopped_utc IS NULL;";
        command.Parameters.AddWithValue("$stopped", stoppedUtc.ToString("O"));
        command.Parameters.AddWithValue("$id", id);
        command.ExecuteNonQuery();
    }

    /// <summary>
    /// Closes sessions left open by a previous service run. The launched process is long
    /// gone, so leaving them "running" would show captures as live forever.
    /// </summary>
    public int CloseOrphanedSessions()
    {
        using var connection = database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText =
            "UPDATE sessions SET stopped_utc = started_utc WHERE stopped_utc IS NULL;";
        return command.ExecuteNonQuery();
    }

    private static CaptureSession Read(SqliteDataReader reader) => new()
    {
        Id = reader.GetInt64(0),
        ExecutablePath = reader.GetString(1),
        ProcessId = reader.IsDBNull(2) ? null : reader.GetInt32(2),
        Mode = reader.GetString(3) == "proxy" ? CaptureMode.Proxy : CaptureMode.Keylog,
        Directory = reader.GetString(4),
        PcapFile = reader.IsDBNull(5) ? null : reader.GetString(5),
        KeylogFile = reader.IsDBNull(6) ? "" : reader.GetString(6),
        StartedUtc = DateTimeOffset.Parse(reader.GetString(7)),
        StoppedUtc = reader.IsDBNull(8) ? null : DateTimeOffset.Parse(reader.GetString(8)),
    };
}
