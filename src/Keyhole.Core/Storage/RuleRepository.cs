using Keyhole.Core.Blocking;
using Microsoft.Data.Sqlite;

namespace Keyhole.Core.Storage;

/// <summary>
/// Stores the rules the user created. The firewall holds the live copy; this is the
/// record of intent, which is what survives a firewall reset or a manual deletion.
/// </summary>
public sealed class RuleRepository(KeyholeDatabase database)
{
    public IReadOnlyList<BlockRule> ListAll()
    {
        using var connection = database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT id, executable_path, sha256, direction, action, is_enabled, note,
                   created_utc, firewall_rule_name
              FROM rules
             ORDER BY created_utc DESC;
            """;

        using var reader = command.ExecuteReader();

        var rules = new List<BlockRule>();
        while (reader.Read())
        {
            rules.Add(Read(reader));
        }

        return rules;
    }

    public BlockRule? FindByPath(string executablePath, RuleDirection direction)
    {
        using var connection = database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT id, executable_path, sha256, direction, action, is_enabled, note,
                   created_utc, firewall_rule_name
              FROM rules
             WHERE executable_path = $path COLLATE NOCASE AND direction = $direction;
            """;
        command.Parameters.AddWithValue("$path", executablePath);
        command.Parameters.AddWithValue("$direction", ToText(direction));

        using var reader = command.ExecuteReader();
        return reader.Read() ? Read(reader) : null;
    }

    /// <summary>
    /// Inserts a rule, or updates the existing one for the same path and direction.
    /// Returns the stored rule with its assigned id.
    /// </summary>
    public BlockRule Upsert(BlockRule rule)
    {
        using var connection = database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO rules (executable_path, sha256, direction, action, is_enabled, note,
                               created_utc, firewall_rule_name)
            VALUES ($path, $sha, $direction, $action, $enabled, $note, $created, $fwName)
            ON CONFLICT (executable_path, direction) DO UPDATE SET
                sha256             = excluded.sha256,
                action             = excluded.action,
                is_enabled         = excluded.is_enabled,
                note               = excluded.note,
                firewall_rule_name = excluded.firewall_rule_name
            RETURNING id, executable_path, sha256, direction, action, is_enabled, note,
                      created_utc, firewall_rule_name;
            """;

        command.Parameters.AddWithValue("$path", rule.ExecutablePath);
        command.Parameters.AddWithValue("$sha", (object?)rule.Sha256 ?? DBNull.Value);
        command.Parameters.AddWithValue("$direction", ToText(rule.Direction));
        command.Parameters.AddWithValue("$action", rule.Action == RuleAction.Block ? "block" : "allow");
        command.Parameters.AddWithValue("$enabled", rule.IsEnabled ? 1 : 0);
        command.Parameters.AddWithValue("$note", (object?)rule.Note ?? DBNull.Value);
        command.Parameters.AddWithValue(
            "$created",
            (rule.CreatedUtc == default ? DateTimeOffset.UtcNow : rule.CreatedUtc).ToString("O"));
        command.Parameters.AddWithValue("$fwName", (object?)rule.FirewallRuleName ?? DBNull.Value);

        using var reader = command.ExecuteReader();
        reader.Read();
        return Read(reader);
    }

    /// <summary>Deletes a rule. Returns false when it was already gone.</summary>
    public bool Delete(long id)
    {
        using var connection = database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM rules WHERE id = $id;";
        command.Parameters.AddWithValue("$id", id);
        return command.ExecuteNonQuery() > 0;
    }

    public BlockRule? FindById(long id)
    {
        using var connection = database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT id, executable_path, sha256, direction, action, is_enabled, note,
                   created_utc, firewall_rule_name
              FROM rules WHERE id = $id;
            """;
        command.Parameters.AddWithValue("$id", id);

        using var reader = command.ExecuteReader();
        return reader.Read() ? Read(reader) : null;
    }

    private static BlockRule Read(SqliteDataReader reader) => new()
    {
        Id = reader.GetInt64(0),
        ExecutablePath = reader.GetString(1),
        Sha256 = reader.IsDBNull(2) ? null : reader.GetString(2),
        Direction = ParseDirection(reader.GetString(3)),
        Action = reader.GetString(4) == "allow" ? RuleAction.Allow : RuleAction.Block,
        IsEnabled = reader.GetInt32(5) != 0,
        Note = reader.IsDBNull(6) ? null : reader.GetString(6),
        CreatedUtc = DateTimeOffset.Parse(reader.GetString(7)),
        FirewallRuleName = reader.IsDBNull(8) ? null : reader.GetString(8),
    };

    /// <summary>Must match the CHECK constraint in the schema exactly.</summary>
    private static string ToText(RuleDirection direction) => direction switch
    {
        RuleDirection.Inbound => "inbound",
        RuleDirection.Both => "both",
        _ => "outbound",
    };

    private static RuleDirection ParseDirection(string value) => value switch
    {
        "inbound" => RuleDirection.Inbound,
        "both" => RuleDirection.Both,
        _ => RuleDirection.Outbound,
    };
}
