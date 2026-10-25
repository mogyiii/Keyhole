using Keyhole.Core.Storage;
using Microsoft.Data.Sqlite;

namespace Keyhole.Tests;

public class MigrationRunnerTests : IDisposable
{
    private readonly string _databaseFile =
        Path.Combine(Path.GetTempPath(), $"keyhole-test-{Guid.NewGuid():n}.sqlite");

    private KeyholeDatabase Database => new(_databaseFile);

    [Fact]
    public void Creates_schema_on_a_fresh_database()
    {
        var version = new MigrationRunner(Database).Migrate();

        Assert.Equal(MigrationRunner.TargetVersion, version);
        Assert.True(File.Exists(_databaseFile));

        foreach (var table in new[] { "processes", "flows", "rules", "sessions", "schema_version" })
        {
            Assert.True(TableExists(table), $"Expected table '{table}' to exist.");
        }
    }

    [Fact]
    public void Is_idempotent()
    {
        var first = new MigrationRunner(Database).Migrate();
        var second = new MigrationRunner(Database).Migrate();

        Assert.Equal(first, second);

        // A second run must not re-stamp migrations it already applied.
        using var connection = Database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM schema_version;";
        Assert.Equal(MigrationRunner.TargetVersion, Convert.ToInt32(command.ExecuteScalar()));
    }

    [Fact]
    public void Refuses_a_database_from_a_newer_build()
    {
        new MigrationRunner(Database).Migrate();

        using (var connection = Database.OpenConnection())
        using (var command = connection.CreateCommand())
        {
            command.CommandText =
                "INSERT INTO schema_version (version, name, applied_utc) VALUES (9999, 'from-the-future', $t);";
            command.Parameters.AddWithValue("$t", DateTimeOffset.UtcNow.ToString("O"));
            command.ExecuteNonQuery();
        }

        // Downgrading would silently drop data, so this must fail loudly rather than proceed.
        Assert.Throws<InvalidOperationException>(() => new MigrationRunner(Database).Migrate());
    }

    [Fact]
    public void Rules_table_rejects_an_unknown_direction()
    {
        new MigrationRunner(Database).Migrate();

        using var connection = Database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO rules (executable_path, direction, action, created_utc)
            VALUES ('C:\sus.exe', 'sideways', 'block', '2026-10-25T00:00:00Z');
            """;

        Assert.Throws<SqliteException>(() => command.ExecuteNonQuery());
    }

    [Fact]
    public void Rules_table_allows_one_rule_per_path_and_direction()
    {
        new MigrationRunner(Database).Migrate();

        using var connection = Database.OpenConnection();

        Insert(connection, @"C:\sus.exe", "outbound");

        // Same executable, other direction: allowed.
        Insert(connection, @"C:\sus.exe", "inbound");

        // Same executable and direction: must collide so the UI cannot create duplicates.
        Assert.Throws<SqliteException>(() => Insert(connection, @"C:\sus.exe", "outbound"));

        static void Insert(SqliteConnection connection, string path, string direction)
        {
            using var command = connection.CreateCommand();
            command.CommandText = """
                INSERT INTO rules (executable_path, direction, action, created_utc)
                VALUES ($p, $d, 'block', '2026-10-25T00:00:00Z');
                """;
            command.Parameters.AddWithValue("$p", path);
            command.Parameters.AddWithValue("$d", direction);
            command.ExecuteNonQuery();
        }
    }

    private bool TableExists(string name)
    {
        using var connection = Database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = $n;";
        command.Parameters.AddWithValue("$n", name);
        return Convert.ToInt32(command.ExecuteScalar()) == 1;
    }

    public void Dispose()
    {
        // Pooled connections keep a handle on the file; clear them so cleanup can delete it.
        SqliteConnection.ClearAllPools();

        foreach (var suffix in new[] { "", "-wal", "-shm" })
        {
            try
            {
                File.Delete(_databaseFile + suffix);
            }
            catch (IOException)
            {
                // A leaked handle during a failing test must not mask the real failure.
            }
        }
    }
}
