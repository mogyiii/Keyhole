using Keyhole.Core.Capture;
using Microsoft.Data.Sqlite;

namespace Keyhole.Core.Storage;

/// <summary>Stores capture sessions so past captures remain findable after a restart.</summary>
public sealed class SessionRepository(KeyholeDatabase database)
{
    public CaptureSession Create(CaptureSession session)
    {
        using var connection = database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO sessions (executable_path, pid, mode, directory, pcap_file, keylog_file,
                                  started_utc, stopped_utc)
            VALUES ($path, $pid, $mode, $dir, NULL, $keylog, $started, NULL)
            RETURNING id, executable_path, pid, mode, directory, keylog_file, started_utc, stopped_utc;
            """;

        command.Parameters.AddWithValue("$path", session.ExecutablePath);
        command.Parameters.AddWithValue("$pid", (object?)session.ProcessId ?? DBNull.Value);
        command.Parameters.AddWithValue("$mode", session.Mode == CaptureMode.Proxy ? "proxy" : "keylog");
        command.Parameters.AddWithValue("$dir", session.Directory);
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
        command.CommandText = """
            SELECT id, executable_path, pid, mode, directory, keylog_file, started_utc, stopped_utc
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
        command.CommandText = """
            SELECT id, executable_path, pid, mode, directory, keylog_file, started_utc, stopped_utc
              FROM sessions WHERE id = $id;
            """;
        command.Parameters.AddWithValue("$id", id);

        using var reader = command.ExecuteReader();
        return reader.Read() ? Read(reader) : null;
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
        KeylogFile = reader.IsDBNull(5) ? "" : reader.GetString(5),
        StartedUtc = DateTimeOffset.Parse(reader.GetString(6)),
        StoppedUtc = reader.IsDBNull(7) ? null : DateTimeOffset.Parse(reader.GetString(7)),
    };
}
