using Microsoft.Data.Sqlite;

namespace Mrbr.Encryption.Data.Identity.Migration.Sqlite;

/// <summary>Writes and fully verifies protected rows in one SQLite shadow table.</summary>
public sealed class SqliteIdentityTokenMigrationBatchProcessor : IIdentityTokenMigrationBatchProcessor
{
    private readonly string _connectionString;
    private readonly SqliteIdentityTokenMigrationNames _names;
    private readonly IIdentityTokenMigrationProtectionAdapter _protection;

    /// <summary>Initializes a processor for one migration execution.</summary>
    public SqliteIdentityTokenMigrationBatchProcessor(
        string connectionString,
        Guid migrationId,
        IIdentityTokenMigrationProtectionAdapter protection)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        ArgumentNullException.ThrowIfNull(protection);
        _connectionString = connectionString;
        _names = new SqliteIdentityTokenMigrationNames(migrationId);
        _protection = protection;
    }

    /// <inheritdoc />
    public async ValueTask<IdentityTokenMigrationResult<int>> WriteOrVerifyBatchAsync(
        IReadOnlyList<LegacyIdentityTokenMigrationRow> sourceRows,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(sourceRows);
        await using SqliteConnection connection = new(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using SqliteTransaction transaction = (SqliteTransaction)await connection
            .BeginTransactionAsync(cancellationToken).ConfigureAwait(false);

        int ready = 0;
        try
        {
            foreach (LegacyIdentityTokenMigrationRow sourceRow in sourceRows)
            {
                cancellationToken.ThrowIfCancellationRequested();
                IdentityTokenMigrationResult<string> hash = _protection.ComputeRoutingHash(sourceRow);
                if (!hash.IsSuccess)
                {
                    return IdentityTokenMigrationResult<int>.Failure(hash.FailureCode);
                }

                IReadOnlyList<ProtectedIdentityTokenMigrationRow> existing = await FindByHashAsync(
                    connection,
                    transaction,
                    hash.Value,
                    cancellationToken).ConfigureAwait(false);
                if (existing.Count > 1)
                {
                    return IdentityTokenMigrationResult<int>.Failure(
                        IdentityTokenMigrationFailureCode.AmbiguousMatch);
                }

                if (existing.Count == 1)
                {
                    IdentityTokenMigrationResult<bool> verified = _protection.Verify(sourceRow, existing[0]);
                    if (!verified.IsSuccess)
                    {
                        return IdentityTokenMigrationResult<int>.Failure(verified.FailureCode);
                    }

                    if (!verified.Value)
                    {
                        return IdentityTokenMigrationResult<int>.Failure(
                            IdentityTokenMigrationFailureCode.HashMismatch);
                    }
                }
                else
                {
                    Guid tokenId = Guid.CreateVersion7();
                    IdentityTokenMigrationResult<ProtectedIdentityTokenMigrationRow> protectedRow =
                        _protection.Protect(sourceRow, tokenId, hash.Value);
                    if (!protectedRow.IsSuccess)
                    {
                        return IdentityTokenMigrationResult<int>.Failure(protectedRow.FailureCode);
                    }

                    if (protectedRow.Value.TokenId != tokenId || tokenId.Version != 7 ||
                        !string.Equals(protectedRow.Value.UserId, sourceRow.UserId, StringComparison.Ordinal) ||
                        string.IsNullOrEmpty(protectedRow.Value.EncryptedLoginProvider) ||
                        string.IsNullOrEmpty(protectedRow.Value.EncryptedName) ||
                        !string.Equals(protectedRow.Value.RoutingHash, hash.Value, StringComparison.Ordinal))
                    {
                        return IdentityTokenMigrationResult<int>.Failure(
                            IdentityTokenMigrationFailureCode.InvalidPayload);
                    }

                    await InsertAsync(connection, transaction, protectedRow.Value, cancellationToken)
                        .ConfigureAwait(false);
                }

                ready++;
            }

            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            return IdentityTokenMigrationResult<int>.Success(ready);
        }
        catch (SqliteException exception) when (exception.SqliteErrorCode == 19)
        {
            await transaction.RollbackAsync(CancellationToken.None).ConfigureAwait(false);
            return IdentityTokenMigrationResult<int>.Failure(
                IdentityTokenMigrationFailureCode.PersistenceConflict);
        }
        catch (FormatException)
        {
            await transaction.RollbackAsync(CancellationToken.None).ConfigureAwait(false);
            return IdentityTokenMigrationResult<int>.Failure(
                IdentityTokenMigrationFailureCode.InvalidPayload);
        }
    }

    /// <inheritdoc />
    public async ValueTask<IdentityTokenMigrationResult<int>> VerifyBatchAsync(
        IReadOnlyList<LegacyIdentityTokenMigrationRow> sourceRows,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(sourceRows);
        await using SqliteConnection connection = new(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);

        int verifiedCount = 0;
        try
        {
            foreach (LegacyIdentityTokenMigrationRow sourceRow in sourceRows)
            {
                cancellationToken.ThrowIfCancellationRequested();
                IdentityTokenMigrationResult<string> hash = _protection.ComputeRoutingHash(sourceRow);
                if (!hash.IsSuccess)
                {
                    return IdentityTokenMigrationResult<int>.Failure(hash.FailureCode);
                }

                IReadOnlyList<ProtectedIdentityTokenMigrationRow> targetRows = await FindByHashAsync(
                    connection,
                    transaction: null,
                    hash.Value,
                    cancellationToken).ConfigureAwait(false);
                if (targetRows.Count == 0)
                {
                    return IdentityTokenMigrationResult<int>.Failure(
                        IdentityTokenMigrationFailureCode.VerificationFailed);
                }

                if (targetRows.Count > 1)
                {
                    return IdentityTokenMigrationResult<int>.Failure(
                        IdentityTokenMigrationFailureCode.AmbiguousMatch);
                }

                IdentityTokenMigrationResult<bool> verified = _protection.Verify(sourceRow, targetRows[0]);
                if (!verified.IsSuccess)
                {
                    return IdentityTokenMigrationResult<int>.Failure(verified.FailureCode);
                }

                if (!verified.Value)
                {
                    return IdentityTokenMigrationResult<int>.Failure(
                        IdentityTokenMigrationFailureCode.HashMismatch);
                }

                verifiedCount++;
            }
        }
        catch (FormatException)
        {
            return IdentityTokenMigrationResult<int>.Failure(
                IdentityTokenMigrationFailureCode.InvalidPayload);
        }

        return IdentityTokenMigrationResult<int>.Success(verifiedCount);
    }

    private async Task<IReadOnlyList<ProtectedIdentityTokenMigrationRow>> FindByHashAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        string routingHash,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            $"SELECT \"TokenId\", \"UserId\", \"LoginProvider\", \"Name\", \"Value\", \"RoutingHash\" " +
            $"FROM \"{_names.ShadowTable}\" WHERE \"RoutingHash\" = $hash LIMIT 2";
        command.Parameters.AddWithValue("$hash", routingHash);
        List<ProtectedIdentityTokenMigrationRow> rows = new(1);
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            rows.Add(new ProtectedIdentityTokenMigrationRow(
                Guid.Parse(reader.GetString(0)),
                reader.GetString(1),
                reader.GetString(2),
                reader.GetString(3),
                reader.IsDBNull(4) ? null : reader.GetString(4),
                reader.GetString(5)));
        }

        return rows;
    }

    private async Task InsertAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ProtectedIdentityTokenMigrationRow row,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            $"INSERT INTO \"{_names.ShadowTable}\" " +
            "(\"TokenId\", \"UserId\", \"LoginProvider\", \"Name\", \"Value\", \"RoutingHash\") " +
            "VALUES ($tokenId, $userId, $provider, $name, $value, $hash)";
        command.Parameters.AddWithValue("$tokenId", row.TokenId.ToString("D"));
        command.Parameters.AddWithValue("$userId", row.UserId);
        command.Parameters.AddWithValue("$provider", row.EncryptedLoginProvider);
        command.Parameters.AddWithValue("$name", row.EncryptedName);
        command.Parameters.AddWithValue("$value", (object?)row.EncryptedValue ?? DBNull.Value);
        command.Parameters.AddWithValue("$hash", row.RoutingHash);
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }
}
