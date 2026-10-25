using Microsoft.Data.Sqlite;

namespace Keyhole.Core.Storage;

/// <summary>
/// Owns the SQLite connection string and hands out connections. Registered as a singleton;
/// SQLite connections are cheap to open, so callers open one per unit of work.
/// </summary>
public sealed class KeyholeDatabase
{
    private readonly string _connectionString;

    public KeyholeDatabase(string? databaseFile = null)
    {
        DatabaseFile = databaseFile ?? KeyholePaths.DatabaseFile;

        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = DatabaseFile,
            Mode = SqliteOpenMode.ReadWriteCreate,
            // The service writes flows continuously while the UI reads; shared cache plus WAL
            // keeps readers from blocking the writer.
            Cache = SqliteCacheMode.Shared,
            Pooling = true,
        }.ToString();
    }

    public string DatabaseFile { get; }

    public SqliteConnection OpenConnection()
    {
        var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using var pragma = connection.CreateCommand();
        pragma.CommandText = """
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA foreign_keys = ON;
            PRAGMA busy_timeout = 5000;
            """;
        pragma.ExecuteNonQuery();

        return connection;
    }
}
