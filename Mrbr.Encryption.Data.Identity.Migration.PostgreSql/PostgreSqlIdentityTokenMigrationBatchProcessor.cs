using Npgsql;

namespace Mrbr.Encryption.Data.Identity.Migration.PostgreSql;

/// <summary>Writes and fully verifies protected rows in one PostgreSQL shadow table.</summary>
public sealed class PostgreSqlIdentityTokenMigrationBatchProcessor : IIdentityTokenMigrationBatchProcessor
{
    private readonly string _connectionString;
    private readonly PostgreSqlIdentityTokenMigrationNames _names;
    private readonly IIdentityTokenMigrationProtectionAdapter _protection;

    public PostgreSqlIdentityTokenMigrationBatchProcessor(
        string connectionString,
        Guid migrationId,
        IIdentityTokenMigrationProtectionAdapter protection)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        ArgumentNullException.ThrowIfNull(protection);
        _connectionString = connectionString;
        _names = new PostgreSqlIdentityTokenMigrationNames(migrationId);
        _protection = protection;
    }

    public async ValueTask<IdentityTokenMigrationResult<int>> WriteOrVerifyBatchAsync(
        IReadOnlyList<LegacyIdentityTokenMigrationRow> sourceRows,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(sourceRows);
        await using NpgsqlConnection connection = new(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken)
            .ConfigureAwait(false);
        int ready = 0;
        try
        {
            foreach (LegacyIdentityTokenMigrationRow sourceRow in sourceRows)
            {
                cancellationToken.ThrowIfCancellationRequested();
                IdentityTokenMigrationResult<string> hash = _protection.ComputeRoutingHash(sourceRow);
                if (!hash.IsSuccess) return Failure(hash.FailureCode);
                IReadOnlyList<ProtectedIdentityTokenMigrationRow> existing = await FindByHashAsync(
                    connection, transaction, hash.Value, cancellationToken).ConfigureAwait(false);
                if (existing.Count > 1) return Failure(IdentityTokenMigrationFailureCode.AmbiguousMatch);
                if (existing.Count == 1)
                {
                    IdentityTokenMigrationResult<bool> verified = _protection.Verify(sourceRow, existing[0]);
                    if (!verified.IsSuccess) return Failure(verified.FailureCode);
                    if (!verified.Value) return Failure(IdentityTokenMigrationFailureCode.HashMismatch);
                }
                else
                {
                    Guid tokenId = Guid.CreateVersion7();
                    IdentityTokenMigrationResult<ProtectedIdentityTokenMigrationRow> protectedRow =
                        _protection.Protect(sourceRow, tokenId, hash.Value);
                    if (!protectedRow.IsSuccess) return Failure(protectedRow.FailureCode);
                    ProtectedIdentityTokenMigrationRow row = protectedRow.Value;
                    if (row.TokenId != tokenId || tokenId.Version != 7 ||
                        !string.Equals(row.UserId, sourceRow.UserId, StringComparison.Ordinal) ||
                        string.IsNullOrEmpty(row.EncryptedLoginProvider) || string.IsNullOrEmpty(row.EncryptedName) ||
                        !string.Equals(row.RoutingHash, hash.Value, StringComparison.Ordinal))
                    {
                        return Failure(IdentityTokenMigrationFailureCode.InvalidPayload);
                    }

                    await InsertAsync(connection, transaction, row, cancellationToken).ConfigureAwait(false);
                }

                ready++;
            }

            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            return IdentityTokenMigrationResult<int>.Success(ready);
        }
        catch (PostgresException exception) when (exception.SqlState == PostgresErrorCodes.UniqueViolation)
        {
            await transaction.RollbackAsync(CancellationToken.None).ConfigureAwait(false);
            return Failure(IdentityTokenMigrationFailureCode.PersistenceConflict);
        }
        catch (FormatException)
        {
            await transaction.RollbackAsync(CancellationToken.None).ConfigureAwait(false);
            return Failure(IdentityTokenMigrationFailureCode.InvalidPayload);
        }
    }

    public async ValueTask<IdentityTokenMigrationResult<int>> VerifyBatchAsync(
        IReadOnlyList<LegacyIdentityTokenMigrationRow> sourceRows,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(sourceRows);
        await using NpgsqlConnection connection = new(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        int count = 0;
        try
        {
            foreach (LegacyIdentityTokenMigrationRow sourceRow in sourceRows)
            {
                IdentityTokenMigrationResult<string> hash = _protection.ComputeRoutingHash(sourceRow);
                if (!hash.IsSuccess) return Failure(hash.FailureCode);
                IReadOnlyList<ProtectedIdentityTokenMigrationRow> targets = await FindByHashAsync(
                    connection, null, hash.Value, cancellationToken).ConfigureAwait(false);
                if (targets.Count == 0) return Failure(IdentityTokenMigrationFailureCode.VerificationFailed);
                if (targets.Count > 1) return Failure(IdentityTokenMigrationFailureCode.AmbiguousMatch);
                IdentityTokenMigrationResult<bool> verified = _protection.Verify(sourceRow, targets[0]);
                if (!verified.IsSuccess) return Failure(verified.FailureCode);
                if (!verified.Value) return Failure(IdentityTokenMigrationFailureCode.HashMismatch);
                count++;
            }
        }
        catch (FormatException)
        {
            return Failure(IdentityTokenMigrationFailureCode.InvalidPayload);
        }

        return IdentityTokenMigrationResult<int>.Success(count);
    }

    private async Task<IReadOnlyList<ProtectedIdentityTokenMigrationRow>> FindByHashAsync(
        NpgsqlConnection connection, NpgsqlTransaction? transaction, string hash, CancellationToken cancellationToken)
    {
        await using NpgsqlCommand command = new(
            $"SELECT \"TokenId\", \"UserId\", \"LoginProvider\", \"Name\", \"Value\", \"RoutingHash\" FROM {Quote(_names.ShadowTable)} " +
            "WHERE \"RoutingHash\" = @hash LIMIT 2", connection, transaction);
        command.Parameters.AddWithValue("hash", hash);
        var rows = new List<ProtectedIdentityTokenMigrationRow>(1);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            rows.Add(new ProtectedIdentityTokenMigrationRow(
                reader.GetGuid(0), reader.GetString(1), reader.GetString(2), reader.GetString(3),
                reader.IsDBNull(4) ? null : reader.GetString(4), reader.GetString(5)));
        }
        return rows;
    }

    private async Task InsertAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction,
        ProtectedIdentityTokenMigrationRow row, CancellationToken cancellationToken)
    {
        await using NpgsqlCommand command = new(
            $"INSERT INTO {Quote(_names.ShadowTable)} " +
            "(\"TokenId\", \"UserId\", \"LoginProvider\", \"Name\", \"Value\", \"RoutingHash\") " +
            "VALUES (@tokenId, @userId, @provider, @name, @value, @hash)", connection, transaction);
        command.Parameters.AddWithValue("tokenId", row.TokenId);
        command.Parameters.AddWithValue("userId", row.UserId);
        command.Parameters.AddWithValue("provider", row.EncryptedLoginProvider);
        command.Parameters.AddWithValue("name", row.EncryptedName);
        command.Parameters.AddWithValue("value", (object?)row.EncryptedValue ?? DBNull.Value);
        command.Parameters.AddWithValue("hash", row.RoutingHash);
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static IdentityTokenMigrationResult<int> Failure(IdentityTokenMigrationFailureCode code) =>
        IdentityTokenMigrationResult<int>.Failure(code);
    private static string Quote(string identifier) => '"' + identifier.Replace("\"", "\"\"", StringComparison.Ordinal) + '"';
}
