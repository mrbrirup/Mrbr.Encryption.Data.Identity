using Npgsql;

namespace Mrbr.Encryption.Data.Identity.Migration.PostgreSql;

/// <summary>Reads a frozen legacy PostgreSQL Identity token table.</summary>
public sealed class PostgreSqlIdentityTokenMigrationSource : IIdentityTokenMigrationSource
{
    private readonly string _connectionString;
    private readonly string _table;

    public PostgreSqlIdentityTokenMigrationSource(string connectionString)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        _connectionString = connectionString;
        _table = "AspNetUserTokens";
    }

    public PostgreSqlIdentityTokenMigrationSource(string connectionString, Guid migrationId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        _connectionString = connectionString;
        _table = new PostgreSqlIdentityTokenMigrationNames(migrationId).LegacyTable;
    }

    public async ValueTask<long> CountAsync(CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = new(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlCommand command = new($"SELECT COUNT(*) FROM {Quote(_table)}", connection);
        return Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false),
            System.Globalization.CultureInfo.InvariantCulture);
    }

    public async ValueTask<IReadOnlyList<LegacyIdentityTokenMigrationRow>> ReadBatchAsync(
        long offset,
        int batchSize,
        CancellationToken cancellationToken)
    {
        if (offset < 0) throw new ArgumentOutOfRangeException(nameof(offset));
        if (batchSize <= 0) throw new ArgumentOutOfRangeException(nameof(batchSize));
        await using NpgsqlConnection connection = new(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlCommand command = new(
            "SELECT \"UserId\", \"LoginProvider\", \"Name\", \"Value\" " +
            $"FROM {Quote(_table)} ORDER BY \"UserId\" COLLATE \"C\", " +
            "\"LoginProvider\" COLLATE \"C\", \"Name\" COLLATE \"C\" LIMIT @limit OFFSET @offset",
            connection);
        command.Parameters.AddWithValue("limit", batchSize);
        command.Parameters.AddWithValue("offset", offset);
        var rows = new List<LegacyIdentityTokenMigrationRow>(batchSize);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            rows.Add(new LegacyIdentityTokenMigrationRow(
                reader.GetString(0), reader.GetString(1), reader.GetString(2),
                reader.IsDBNull(3) ? null : reader.GetString(3)));
        }

        return rows;
    }

    private static string Quote(string identifier) => '"' + identifier.Replace("\"", "\"\"", StringComparison.Ordinal) + '"';
}
