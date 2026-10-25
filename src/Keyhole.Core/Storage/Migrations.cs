namespace Keyhole.Core.Storage;

/// <summary>
/// The ordered schema history. Migrations are append-only: never edit a shipped entry,
/// add a new one. <see cref="MigrationRunner"/> applies whatever the database is missing.
/// </summary>
internal static class Migrations
{
    internal sealed record Migration(int Version, string Name, string Sql);

    internal static readonly IReadOnlyList<Migration> All =
    [
        new(1, "initial-schema", """
            -- Distinct executables Keyhole has seen. Identity is path + hash so that replacing
            -- a binary at a known path shows up as a new row rather than inheriting its rules.
            CREATE TABLE processes (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                executable_path TEXT    NOT NULL,
                sha256          TEXT    NULL,
                display_name    TEXT    NULL,
                publisher       TEXT    NULL,
                is_signed       INTEGER NOT NULL DEFAULT 0,
                first_seen_utc  TEXT    NOT NULL,
                last_seen_utc   TEXT    NOT NULL,
                UNIQUE (executable_path, sha256)
            );

            -- One row per observed connection, aggregated rather than per packet: a packet-level
            -- table would grow without bound, and the UI only ever shows per-connection totals.
            CREATE TABLE flows (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                process_id      INTEGER NOT NULL REFERENCES processes(id) ON DELETE CASCADE,
                pid             INTEGER NOT NULL,
                protocol        TEXT    NOT NULL,
                local_address   TEXT    NOT NULL,
                local_port      INTEGER NOT NULL,
                remote_address  TEXT    NOT NULL,
                remote_port     INTEGER NOT NULL,
                remote_hostname TEXT    NULL,
                bytes_sent      INTEGER NOT NULL DEFAULT 0,
                bytes_received  INTEGER NOT NULL DEFAULT 0,
                started_utc     TEXT    NOT NULL,
                last_active_utc TEXT    NOT NULL,
                ended_utc       TEXT    NULL
            );

            CREATE INDEX idx_flows_process   ON flows(process_id, last_active_utc DESC);
            CREATE INDEX idx_flows_active    ON flows(last_active_utc DESC);
            CREATE INDEX idx_flows_remote    ON flows(remote_address);

            -- Manual block rules only: the user picks what to cut off. One row per executable
            -- and direction, mirrored into a Windows Firewall rule by the service.
            CREATE TABLE rules (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                executable_path  TEXT    NOT NULL,
                sha256           TEXT    NULL,
                direction        TEXT    NOT NULL CHECK (direction IN ('outbound', 'inbound', 'both')),
                action           TEXT    NOT NULL CHECK (action IN ('block', 'allow')),
                is_enabled       INTEGER NOT NULL DEFAULT 1,
                note             TEXT    NULL,
                created_utc      TEXT    NOT NULL,
                -- Name of the backing Windows Firewall rule, so orphans can be reconciled.
                firewall_rule_name TEXT  NULL,
                UNIQUE (executable_path, direction)
            );

            -- Capture sessions: a launched process plus its pcap and TLS keylog on disk.
            CREATE TABLE sessions (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                executable_path  TEXT    NOT NULL,
                pid              INTEGER NULL,
                mode             TEXT    NOT NULL CHECK (mode IN ('keylog', 'proxy')),
                directory        TEXT    NOT NULL,
                pcap_file        TEXT    NULL,
                keylog_file      TEXT    NULL,
                started_utc      TEXT    NOT NULL,
                stopped_utc      TEXT    NULL
            );
            """),

        new(2, "normalise-unhashed-processes", """
            -- SQLite treats NULLs as distinct in a UNIQUE constraint, so a process row with
            -- sha256 IS NULL never conflicts with itself: the upsert in FlowRepository would
            -- insert a duplicate on every sample instead of updating. '' is the "not computed
            -- yet" sentinel; normalise any rows written before that was understood.
            UPDATE processes SET sha256 = '' WHERE sha256 IS NULL;
            """),
    ];
}
