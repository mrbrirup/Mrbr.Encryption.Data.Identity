using Microsoft.Data.Sqlite;

namespace Mrbr.Encryption.Data.Identity.Migration.Sqlite;

/// <summary>Reads a frozen legacy SQLite Identity token table.</summary>
public sealed class SqliteIdentityTokenMigrationSource : IIdentityTokenMigrationSource
{
    private readonly string _connectionString;
    private readonly string _table;

    /// <summary>Initializes a source over the conventional legacy <c>AspNetUserTokens</c> table.</summary>
    public SqliteIdentityTokenMigrationSource(string connectionString)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        _connectionString = connectionString;
        _table = "AspNetUserTokens";
    }

    /// <summary>Initializes a source over the migration-specific retained legacy table after cutover.</summary>
    public SqliteIdentityTokenMigrationSource(string connectionString, Guid migrationId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        _connectionString = connectionString;
        _table = new SqliteIdentityTokenMigrationNames(migrationId).LegacyTable;
    }

    /// <inheritdoc />
    public async ValueTask<long> CountAsync(CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = new(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = $"SELECT COUNT(*) FROM \"{_table}\"";
        object? value = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        return Convert.ToInt64(value, System.Globalization.CultureInfo.InvariantCulture);
    }

    /// <inheritdoc />
    public async ValueTask<IReadOnlyList<LegacyIdentityTokenMigrationRow>> ReadBatchAsync(
        long offset,
        int batchSize,
        CancellationToken cancellationToken)
    {
        if (offset < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(offset));
        }

        if (batchSize <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(batchSize));
        }

        await using SqliteConnection connection = new(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            "SELECT \"UserId\", \"LoginProvider\", \"Name\", \"Value\" " +
            $"FROM \"{_table}\" " +
            "ORDER BY \"UserId\" COLLATE BINARY, \"LoginProvider\" COLLATE BINARY, \"Name\" COLLATE BINARY " +
            "LIMIT $limit OFFSET $offset";
        command.Parameters.AddWithValue("$limit", batchSize);
        command.Parameters.AddWithValue("$offset", offset);

        List<LegacyIdentityTokenMigrationRow> rows = new(batchSize);
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            rows.Add(new LegacyIdentityTokenMigrationRow(
                reader.GetString(0),
                reader.GetString(1),
                reader.GetString(2),
                reader.IsDBNull(3) ? null : reader.GetString(3)));
        }

        return rows;
    }
}
