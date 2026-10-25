using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Keyhole.Core.Storage;

/// <summary>
/// Brings the database up to the latest schema version. Idempotent, so the service can
/// call it unconditionally at every startup.
/// </summary>
public sealed class MigrationRunner(KeyholeDatabase database, ILogger<MigrationRunner>? logger = null)
{
    private readonly ILogger _logger = logger ?? NullLogger<MigrationRunner>.Instance;

    /// <summary>The schema version this build expects.</summary>
    public static int TargetVersion => Migrations.All.Max(m => m.Version);

    /// <summary>Applies pending migrations and returns the resulting schema version.</summary>
    public int Migrate()
    {
        using var connection = database.OpenConnection();

        EnsureVersionTable(connection);
        var current = ReadCurrentVersion(connection);

        if (current > TargetVersion)
        {
            throw new InvalidOperationException(
                $"Database at {database.DatabaseFile} is schema version {current}, but this build " +
                $"only understands {TargetVersion}. A newer Keyhole wrote it; upgrade instead of downgrading.");
        }

        var pending = Migrations.All.Where(m => m.Version > current).OrderBy(m => m.Version).ToList();
        if (pending.Count == 0)
        {
            _logger.LogDebug("Database schema already at version {Version}.", current);
            return current;
        }

        _logger.LogInformation(
            "Migrating database from version {From} to {To} ({Count} migrations).",
            current, TargetVersion, pending.Count);

        foreach (var migration in pending)
        {
            // Each migration gets its own transaction: a failure leaves the database at the last
            // good version rather than half-applied.
            using var transaction = connection.BeginTransaction();

            using (var command = connection.CreateCommand())
            {
                command.Transaction = transaction;
                command.CommandText = migration.Sql;
                command.ExecuteNonQuery();
            }

            using (var stamp = connection.CreateCommand())
            {
                stamp.Transaction = transaction;
                stamp.CommandText =
                    "INSERT INTO schema_version (version, name, applied_utc) VALUES ($v, $n, $t);";
                stamp.Parameters.AddWithValue("$v", migration.Version);
                stamp.Parameters.AddWithValue("$n", migration.Name);
                stamp.Parameters.AddWithValue("$t", DateTimeOffset.UtcNow.ToString("O"));
                stamp.ExecuteNonQuery();
            }

            transaction.Commit();
            _logger.LogInformation("Applied migration {Version} ({Name}).", migration.Version, migration.Name);
        }

        return TargetVersion;
    }

    private static void EnsureVersionTable(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS schema_version (
                version     INTEGER PRIMARY KEY,
                name        TEXT NOT NULL,
                applied_utc TEXT NOT NULL
            );
            """;
        command.ExecuteNonQuery();
    }

    private static int ReadCurrentVersion(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COALESCE(MAX(version), 0) FROM schema_version;";
        return Convert.ToInt32(command.ExecuteScalar());
    }
}
