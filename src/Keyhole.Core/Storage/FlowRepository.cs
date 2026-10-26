using Keyhole.Core.Monitoring;
using Microsoft.Data.Sqlite;
using System.Data;

namespace Keyhole.Core.Storage;

/// <summary>
/// Writes observed flows to SQLite and reads back history.
/// Processes are upserted first so flows always reference a real row.
/// </summary>
public sealed class FlowRepository(KeyholeDatabase database)
{
    /// <summary>
    /// Sentinel for "hash not computed yet". See the upsert for why this is not NULL.
    /// </summary>
    public const string HashNotComputed = "";

    /// <summary>
    /// Persists opened and closed flows in one transaction. Batching matters: a busy
    /// machine opens dozens of connections per sample, and a transaction each would
    /// turn monitoring into a disk-bound workload.
    /// </summary>
    public void RecordSample(SampleResult sample)
    {
        if (sample.Opened.Count == 0 && sample.Closed.Count == 0)
        {
            return;
        }

        using var connection = database.OpenConnection();
        using var transaction = connection.BeginTransaction();

        foreach (var flow in sample.Opened)
        {
            var processId = UpsertProcess(connection, transaction, flow);
            InsertFlow(connection, transaction, flow, processId);
        }

        foreach (var flow in sample.Closed)
        {
            CloseFlow(connection, transaction, flow);
        }

        transaction.Commit();
    }

    private static long UpsertProcess(SqliteConnection connection, SqliteTransaction transaction, TrackedFlow flow)
    {
        var identity = flow.Process;

        // Processes Keyhole cannot read a path for still need a stable row, otherwise
        // every sample would insert a duplicate. The display name stands in as identity.
        var path = identity.ExecutablePath ?? $"<unknown>:{identity.DisplayName}";
        var now = DateTimeOffset.UtcNow.ToString("O");

        using var upsert = connection.CreateCommand();
        upsert.Transaction = transaction;
        upsert.CommandText = """
            INSERT INTO processes (executable_path, sha256, display_name, publisher, is_signed,
                                   first_seen_utc, last_seen_utc)
            VALUES ($path, $sha, $name, $publisher, $signed, $now, $now)
            ON CONFLICT (executable_path, sha256) DO UPDATE SET
                last_seen_utc = $now,
                display_name  = excluded.display_name,
                publisher     = excluded.publisher,
                is_signed     = excluded.is_signed
            RETURNING id;
            """;

        upsert.Parameters.AddWithValue("$path", path);

        // Empty string, never NULL: SQLite treats NULLs as distinct in a UNIQUE constraint,
        // so (path, NULL) would never conflict with itself and every sample would insert
        // a duplicate process row. Hashing on first sight would stall the loop anyway; M4
        // computes the hash when a rule is created, which is when identity must be pinned.
        upsert.Parameters.AddWithValue("$sha", HashNotComputed);
        upsert.Parameters.AddWithValue("$name", identity.DisplayName);
        upsert.Parameters.AddWithValue("$publisher", (object?)identity.Publisher ?? DBNull.Value);
        upsert.Parameters.AddWithValue("$signed", identity.Signature == SignatureStatus.Valid ? 1 : 0);
        upsert.Parameters.AddWithValue("$now", now);

        return Convert.ToInt64(upsert.ExecuteScalar());
    }

    private static void InsertFlow(
        SqliteConnection connection, SqliteTransaction transaction, TrackedFlow flow, long processRowId)
    {
        using var insert = connection.CreateCommand();
        insert.Transaction = transaction;
        insert.CommandText = """
            INSERT INTO flows (process_id, pid, protocol, local_address, local_port,
                               remote_address, remote_port, remote_hostname,
                               bytes_sent, bytes_received, started_utc, last_active_utc)
            VALUES ($processId, $pid, $protocol, $localAddr, $localPort,
                    $remoteAddr, $remotePort, $hostname,
                    $sent, $received, $started, $lastActive);
            """;

        insert.Parameters.AddWithValue("$processId", processRowId);
        insert.Parameters.AddWithValue("$pid", flow.Connection.ProcessId);
        insert.Parameters.AddWithValue("$protocol", flow.Connection.Protocol.ToString().ToUpperInvariant());
        insert.Parameters.AddWithValue("$localAddr", flow.Connection.LocalAddress.ToString());
        insert.Parameters.AddWithValue("$localPort", flow.Connection.LocalPort);
        insert.Parameters.AddWithValue("$remoteAddr", flow.Connection.RemoteAddress.ToString());
        insert.Parameters.AddWithValue("$remotePort", flow.Connection.RemotePort);
        insert.Parameters.AddWithValue("$hostname", (object?)flow.RemoteHostname ?? DBNull.Value);
        insert.Parameters.AddWithValue("$sent", flow.BytesSent);
        insert.Parameters.AddWithValue("$received", flow.BytesReceived);
        insert.Parameters.AddWithValue("$started", flow.StartedUtc.ToString("O"));
        insert.Parameters.AddWithValue("$lastActive", flow.LastSeenUtc.ToString("O"));

        insert.ExecuteNonQuery();
    }

    private static void CloseFlow(SqliteConnection connection, SqliteTransaction transaction, TrackedFlow flow)
    {
        using var update = connection.CreateCommand();
        update.Transaction = transaction;

        // Matches the most recent still-open row for this four-tuple. The same endpoints
        // can be reused over time, so closing them all would rewrite history.
        update.CommandText = """
            UPDATE flows
               SET ended_utc       = $ended,
                   last_active_utc = $lastActive,
                   remote_hostname = COALESCE($hostname, remote_hostname),
                   bytes_sent      = $sent,
                   bytes_received  = $received
             WHERE id = (
                 SELECT id FROM flows
                  WHERE pid = $pid
                    AND protocol = $protocol
                    AND local_port = $localPort
                    AND remote_address = $remoteAddr
                    AND remote_port = $remotePort
                    AND ended_utc IS NULL
                  ORDER BY started_utc DESC
                  LIMIT 1
             );
            """;

        update.Parameters.AddWithValue("$ended", (flow.EndedUtc ?? DateTimeOffset.UtcNow).ToString("O"));
        update.Parameters.AddWithValue("$lastActive", flow.LastSeenUtc.ToString("O"));
        update.Parameters.AddWithValue("$hostname", (object?)flow.RemoteHostname ?? DBNull.Value);
        update.Parameters.AddWithValue("$sent", flow.BytesSent);
        update.Parameters.AddWithValue("$received", flow.BytesReceived);
        update.Parameters.AddWithValue("$pid", flow.Connection.ProcessId);
        update.Parameters.AddWithValue("$protocol", flow.Connection.Protocol.ToString().ToUpperInvariant());
        update.Parameters.AddWithValue("$localPort", flow.Connection.LocalPort);
        update.Parameters.AddWithValue("$remoteAddr", flow.Connection.RemoteAddress.ToString());
        update.Parameters.AddWithValue("$remotePort", flow.Connection.RemotePort);

        update.ExecuteNonQuery();
    }

    /// <summary>
    /// Writes current byte totals for flows that are still open, and returns how many rows
    /// were updated.
    ///
    /// Without this a flow's totals only ever reach the database when it closes, so any
    /// connection still open when the service stops loses its traffic from history
    /// permanently — and long-lived connections are exactly the ones worth looking back at.
    /// Called on a slow interval rather than every sample: this is history, and the live
    /// view reads the tracker directly.
    /// </summary>
    public int UpdateActiveBytes(IEnumerable<TrackedFlow> flows)
    {
        var active = flows.Where(f => f.IsActive && (f.BytesSent > 0 || f.BytesReceived > 0)).ToList();
        if (active.Count == 0)
        {
            return 0;
        }

        using var connection = database.OpenConnection();
        using var transaction = connection.BeginTransaction();

        using var update = connection.CreateCommand();
        update.Transaction = transaction;

        // Matches the most recent still-open row for this four-tuple, the same way
        // CloseFlow does, so the two cannot disagree about which row a flow owns.
        update.CommandText = """
            UPDATE flows
               SET bytes_sent      = $sent,
                   bytes_received  = $received,
                   last_active_utc = $lastActive,
                   remote_hostname = COALESCE($hostname, remote_hostname)
             WHERE id = (
                 SELECT id FROM flows
                  WHERE pid = $pid
                    AND protocol = $protocol
                    AND local_port = $localPort
                    AND remote_address = $remoteAddr
                    AND remote_port = $remotePort
                    AND ended_utc IS NULL
                  ORDER BY started_utc DESC
                  LIMIT 1
             );
            """;

        var sent = update.Parameters.Add("$sent", SqliteType.Integer);
        var received = update.Parameters.Add("$received", SqliteType.Integer);
        var lastActive = update.Parameters.Add("$lastActive", SqliteType.Text);
        var hostname = update.Parameters.Add("$hostname", SqliteType.Text);
        var pid = update.Parameters.Add("$pid", SqliteType.Integer);
        var protocol = update.Parameters.Add("$protocol", SqliteType.Text);
        var localPort = update.Parameters.Add("$localPort", SqliteType.Integer);
        var remoteAddr = update.Parameters.Add("$remoteAddr", SqliteType.Text);
        var remotePort = update.Parameters.Add("$remotePort", SqliteType.Integer);

        var updated = 0;
        foreach (var flow in active)
        {
            sent.Value = flow.BytesSent;
            received.Value = flow.BytesReceived;
            lastActive.Value = flow.LastSeenUtc.ToString("O");
            hostname.Value = (object?)flow.RemoteHostname ?? DBNull.Value;
            pid.Value = flow.Connection.ProcessId;
            protocol.Value = flow.Connection.Protocol.ToString().ToUpperInvariant();
            localPort.Value = flow.Connection.LocalPort;
            remoteAddr.Value = flow.Connection.RemoteAddress.ToString();
            remotePort.Value = flow.Connection.RemotePort;

            updated += update.ExecuteNonQuery();
        }

        transaction.Commit();
        return updated;
    }

    /// <summary>
    /// Closes flows left open by a previous service run and returns how many.
    ///
    /// A flow is only marked ended when the tracker sees it disappear. If the service
    /// stops while connections are live, those rows stay open forever and history would
    /// show them as still active years later. Their true end time is unknown, so the last
    /// time they were observed is the honest answer.
    /// </summary>
    public int CloseOrphanedFlows()
    {
        using var connection = database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "UPDATE flows SET ended_utc = last_active_utc WHERE ended_utc IS NULL;";
        return command.ExecuteNonQuery();
    }

    /// <summary>Total flows recorded. Used by tests and diagnostics.</summary>
    public long CountFlows()
    {
        using var connection = database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM flows;";
        return Convert.ToInt64(command.ExecuteScalar());
    }

    /// <summary>Deletes flow history older than <paramref name="retention"/>.</summary>
    public int PruneOlderThan(TimeSpan retention)
    {
        using var connection = database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM flows WHERE last_active_utc < $cutoff;";
        command.Parameters.AddWithValue("$cutoff", (DateTimeOffset.UtcNow - retention).ToString("O"));
        return command.ExecuteNonQuery();
    }
}
