using Microsoft.Data.Sqlite;

namespace Mrbr.Encryption.Data.Identity.Migration.Sqlite;

/// <summary>Creates and swaps SQLite token tables for one explicit offline migration.</summary>
public sealed class SqliteIdentityTokenMigrationSchemaExecutor
{
    private readonly string _connectionString;
    private readonly SqliteIdentityTokenMigrationNames _names;

    /// <summary>Initializes an executor for one migration execution.</summary>
    public SqliteIdentityTokenMigrationSchemaExecutor(string connectionString, Guid migrationId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        var builder = new SqliteConnectionStringBuilder(connectionString)
        {
            Pooling = false
        };
        _connectionString = builder.ToString();
        _names = new SqliteIdentityTokenMigrationNames(migrationId);
    }

    /// <summary>Validates the frozen legacy database without mutating its schema and returns its row count.</summary>
    public async ValueTask<IdentityTokenMigrationResult<long>> ValidatePreflightAsync(
        CancellationToken cancellationToken = default)
    {
        await using SqliteConnection connection = new(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        if (!await LegacySchemaIsValidAsync(connection, _names.ApplicationTable, cancellationToken)
                .ConfigureAwait(false))
        {
            return IdentityTokenMigrationResult<long>.Failure(
                IdentityTokenMigrationFailureCode.InvalidSourceRow);
        }

        if (await MigrationTableExistsAsync(connection, cancellationToken).ConfigureAwait(false))
        {
            return IdentityTokenMigrationResult<long>.Failure(
                IdentityTokenMigrationFailureCode.InvalidStageTransition);
        }

        if (!await ForeignKeysAreValidAsync(connection, transaction: null, cancellationToken).ConfigureAwait(false) ||
            !await IntegrityIsValidAsync(connection, transaction: null, cancellationToken).ConfigureAwait(false))
        {
            return IdentityTokenMigrationResult<long>.Failure(
                IdentityTokenMigrationFailureCode.VerificationFailed);
        }

        long sourceRows = await CountRowsAsync(connection, _names.ApplicationTable, cancellationToken)
            .ConfigureAwait(false);
        return IdentityTokenMigrationResult<long>.Success(sourceRows);
    }

    private static async Task<bool> MigrationTableExistsAsync(
        SqliteConnection connection,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND " +
            "(name GLOB 'AspNetUserTokens_MrbrProtected_*' OR name GLOB 'AspNetUserTokens_MrbrLegacy_*');";
        return Convert.ToInt64(
            await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false),
            System.Globalization.CultureInfo.InvariantCulture) != 0;
    }

    /// <summary>Creates an empty protected shadow table and advances the durable checkpoint.</summary>
    public async ValueTask<IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint>> CreateShadowSchemaAsync(
        IdentityTokenMigrationCheckpoint checkpoint,
        IIdentityTokenMigrationCheckpointStore checkpointStore,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);
        ArgumentNullException.ThrowIfNull(checkpointStore);
        if (checkpoint.Stage != IdentityTokenMigrationStage.PreflightPassed)
        {
            return Failure(IdentityTokenMigrationFailureCode.InvalidStageTransition);
        }

        await using SqliteConnection connection = new(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        if (!await LegacySchemaIsValidAsync(connection, _names.ApplicationTable, cancellationToken).ConfigureAwait(false))
        {
            return Failure(IdentityTokenMigrationFailureCode.InvalidSourceRow);
        }

        if (await CountRowsAsync(connection, _names.ApplicationTable, cancellationToken).ConfigureAwait(false) !=
            checkpoint.ExpectedSourceRows)
        {
            return Failure(IdentityTokenMigrationFailureCode.SourceChanged);
        }

        bool shadowExists = await TableExistsAsync(connection, _names.ShadowTable, cancellationToken)
            .ConfigureAwait(false);
        if (await TableExistsAsync(connection, _names.LegacyTable, cancellationToken).ConfigureAwait(false))
        {
            return Failure(IdentityTokenMigrationFailureCode.InvalidStageTransition);
        }

        if (shadowExists)
        {
            if (!await ProtectedSchemaIsValidAsync(connection, _names.ShadowTable, cancellationToken)
                    .ConfigureAwait(false) ||
                await CountRowsAsync(connection, _names.ShadowTable, cancellationToken).ConfigureAwait(false) != 0)
            {
                return Failure(IdentityTokenMigrationFailureCode.InvalidStageTransition);
            }

            return await AdvanceAndSaveAsync(
                checkpoint,
                IdentityTokenMigrationStage.ShadowSchemaCreated,
                checkpointStore,
                cancellationToken).ConfigureAwait(false);
        }

        await using SqliteTransaction transaction = (SqliteTransaction)await connection
            .BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            $"CREATE TABLE \"{_names.ShadowTable}\" (" +
            "\"TokenId\" TEXT NOT NULL CONSTRAINT \"PK_MrbrProtectedUserTokens\" PRIMARY KEY, " +
            "\"UserId\" TEXT NOT NULL, " +
            "\"LoginProvider\" TEXT NOT NULL, " +
            "\"Name\" TEXT NOT NULL, " +
            "\"Value\" TEXT NULL, " +
            "\"RoutingHash\" TEXT NOT NULL, " +
            "CONSTRAINT \"FK_MrbrProtectedUserTokens_AspNetUsers_UserId\" " +
            "FOREIGN KEY (\"UserId\") REFERENCES \"AspNetUsers\" (\"Id\") ON DELETE CASCADE);" +
            $"CREATE UNIQUE INDEX \"{_names.ShadowRouteIndex}\" ON \"{_names.ShadowTable}\" (\"RoutingHash\");" +
            $"CREATE INDEX \"{_names.ShadowUserIndex}\" ON \"{_names.ShadowTable}\" (\"UserId\");";
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);

        return await AdvanceAndSaveAsync(
            checkpoint,
            IdentityTokenMigrationStage.ShadowSchemaCreated,
            checkpointStore,
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Swaps the fully verified protected table into the conventional application name.</summary>
    public async ValueTask<IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint>> CutoverAsync(
        IdentityTokenMigrationCheckpoint checkpoint,
        IIdentityTokenMigrationCheckpointStore checkpointStore,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);
        ArgumentNullException.ThrowIfNull(checkpointStore);
        if (checkpoint.Stage != IdentityTokenMigrationStage.Verified)
        {
            return Failure(IdentityTokenMigrationFailureCode.InvalidStageTransition);
        }

        await using SqliteConnection connection = new(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        bool applicationExists = await TableExistsAsync(connection, _names.ApplicationTable, cancellationToken)
            .ConfigureAwait(false);
        bool shadowExists = await TableExistsAsync(connection, _names.ShadowTable, cancellationToken)
            .ConfigureAwait(false);
        bool legacyExists = await TableExistsAsync(connection, _names.LegacyTable, cancellationToken)
            .ConfigureAwait(false);

        if (applicationExists && !shadowExists && legacyExists &&
            await ProtectedSchemaIsValidAsync(connection, _names.ApplicationTable, cancellationToken)
                .ConfigureAwait(false) &&
            await LegacySchemaIsValidAsync(connection, _names.LegacyTable, cancellationToken)
                .ConfigureAwait(false) &&
            await CountRowsAsync(connection, _names.ApplicationTable, cancellationToken).ConfigureAwait(false) ==
                checkpoint.ExpectedSourceRows &&
            await CountRowsAsync(connection, _names.LegacyTable, cancellationToken).ConfigureAwait(false) ==
                checkpoint.ExpectedSourceRows &&
            await ForeignKeysAreValidAsync(connection, transaction: null, cancellationToken).ConfigureAwait(false) &&
            await IntegrityIsValidAsync(connection, transaction: null, cancellationToken).ConfigureAwait(false))
        {
            return await AdvanceAndSaveAsync(
                checkpoint,
                IdentityTokenMigrationStage.CutoverComplete,
                checkpointStore,
                cancellationToken).ConfigureAwait(false);
        }

        if (!applicationExists || !shadowExists || legacyExists ||
            !await LegacySchemaIsValidAsync(connection, _names.ApplicationTable, cancellationToken)
                .ConfigureAwait(false) ||
            !await ProtectedSchemaIsValidAsync(connection, _names.ShadowTable, cancellationToken)
                .ConfigureAwait(false) ||
            await CountRowsAsync(connection, _names.ApplicationTable, cancellationToken).ConfigureAwait(false) !=
                checkpoint.ExpectedSourceRows ||
            await CountRowsAsync(connection, _names.ShadowTable, cancellationToken).ConfigureAwait(false) !=
                checkpoint.ExpectedSourceRows)
        {
            return Failure(IdentityTokenMigrationFailureCode.VerificationFailed);
        }

        await SetExclusiveLockingAsync(connection, cancellationToken).ConfigureAwait(false);
        await using SqliteTransaction transaction = (SqliteTransaction)await connection
            .BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await RenameAsync(connection, transaction, _names.ApplicationTable, _names.LegacyTable, cancellationToken)
            .ConfigureAwait(false);
        await RenameAsync(connection, transaction, _names.ShadowTable, _names.ApplicationTable, cancellationToken)
            .ConfigureAwait(false);
        if (!await ForeignKeysAreValidAsync(connection, transaction, cancellationToken).ConfigureAwait(false) ||
            !await IntegrityIsValidAsync(connection, transaction, cancellationToken).ConfigureAwait(false))
        {
            await transaction.RollbackAsync(CancellationToken.None).ConfigureAwait(false);
            return Failure(IdentityTokenMigrationFailureCode.VerificationFailed);
        }

        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        await connection.CloseAsync().ConfigureAwait(false);
        return await AdvanceAndSaveAsync(
            checkpoint,
            IdentityTokenMigrationStage.CutoverComplete,
            checkpointStore,
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Restores the legacy table before any protected application write has been accepted.</summary>
    public async ValueTask<IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint>> RollbackCutoverAsync(
        IdentityTokenMigrationCheckpoint checkpoint,
        IIdentityTokenMigrationCheckpointStore checkpointStore,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);
        ArgumentNullException.ThrowIfNull(checkpointStore);
        IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint> allowed =
            IdentityTokenMigrationStateMachine.ValidateTableSwapRollback(checkpoint);
        if (!allowed.IsSuccess)
        {
            return allowed;
        }

        await using SqliteConnection connection = new(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        bool applicationExists = await TableExistsAsync(connection, _names.ApplicationTable, cancellationToken)
            .ConfigureAwait(false);
        bool shadowExists = await TableExistsAsync(connection, _names.ShadowTable, cancellationToken)
            .ConfigureAwait(false);
        bool legacyExists = await TableExistsAsync(connection, _names.LegacyTable, cancellationToken)
            .ConfigureAwait(false);

        if (applicationExists && shadowExists && !legacyExists &&
            await LegacySchemaIsValidAsync(connection, _names.ApplicationTable, cancellationToken)
                .ConfigureAwait(false) &&
            await ProtectedSchemaIsValidAsync(connection, _names.ShadowTable, cancellationToken)
                .ConfigureAwait(false) &&
            await CountRowsAsync(connection, _names.ApplicationTable, cancellationToken).ConfigureAwait(false) ==
                checkpoint.ExpectedSourceRows &&
            await CountRowsAsync(connection, _names.ShadowTable, cancellationToken).ConfigureAwait(false) ==
                checkpoint.ExpectedSourceRows &&
            await ForeignKeysAreValidAsync(connection, transaction: null, cancellationToken).ConfigureAwait(false) &&
            await IntegrityIsValidAsync(connection, transaction: null, cancellationToken).ConfigureAwait(false))
        {
            return await RecordRollbackAndSaveAsync(checkpoint, checkpointStore, cancellationToken)
                .ConfigureAwait(false);
        }

        if (!applicationExists || shadowExists || !legacyExists ||
            !await ProtectedSchemaIsValidAsync(connection, _names.ApplicationTable, cancellationToken)
                .ConfigureAwait(false) ||
            !await LegacySchemaIsValidAsync(connection, _names.LegacyTable, cancellationToken)
                .ConfigureAwait(false) ||
            await CountRowsAsync(connection, _names.ApplicationTable, cancellationToken).ConfigureAwait(false) !=
                checkpoint.ExpectedSourceRows ||
            await CountRowsAsync(connection, _names.LegacyTable, cancellationToken).ConfigureAwait(false) !=
                checkpoint.ExpectedSourceRows)
        {
            return Failure(IdentityTokenMigrationFailureCode.VerificationFailed);
        }

        await SetExclusiveLockingAsync(connection, cancellationToken).ConfigureAwait(false);
        await using SqliteTransaction transaction = (SqliteTransaction)await connection
            .BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await RenameAsync(connection, transaction, _names.ApplicationTable, _names.ShadowTable, cancellationToken)
            .ConfigureAwait(false);
        await RenameAsync(connection, transaction, _names.LegacyTable, _names.ApplicationTable, cancellationToken)
            .ConfigureAwait(false);
        if (!await ForeignKeysAreValidAsync(connection, transaction, cancellationToken).ConfigureAwait(false) ||
            !await IntegrityIsValidAsync(connection, transaction, cancellationToken).ConfigureAwait(false))
        {
            await transaction.RollbackAsync(CancellationToken.None).ConfigureAwait(false);
            return Failure(IdentityTokenMigrationFailureCode.VerificationFailed);
        }

        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        await connection.CloseAsync().ConfigureAwait(false);
        return await RecordRollbackAndSaveAsync(checkpoint, checkpointStore, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>Drops the retained plaintext table after runtime verification, write acceptance, and explicit approval.</summary>
    public async ValueTask<IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint>> RemoveRetainedPlaintextAsync(
        IdentityTokenMigrationCheckpoint checkpoint,
        IdentityTokenMigrationPlaintextRemovalApproval approval,
        IIdentityTokenMigrationCheckpointStore checkpointStore,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);
        ArgumentNullException.ThrowIfNull(approval);
        ArgumentNullException.ThrowIfNull(checkpointStore);
        if (checkpoint.Stage != IdentityTokenMigrationStage.RuntimeVerified ||
            !checkpoint.ProtectedWritesAccepted)
        {
            return Failure(IdentityTokenMigrationFailureCode.InvalidStageTransition);
        }

        if (!approval.IsApprovedFor(checkpoint.MigrationId))
        {
            return Failure(IdentityTokenMigrationFailureCode.OperatorApprovalRequired);
        }

        await using SqliteConnection connection = new(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        if (!await ProtectedSchemaIsValidAsync(connection, _names.ApplicationTable, cancellationToken)
                .ConfigureAwait(false) ||
            !await ForeignKeysAreValidAsync(connection, transaction: null, cancellationToken).ConfigureAwait(false) ||
            !await IntegrityIsValidAsync(connection, transaction: null, cancellationToken).ConfigureAwait(false))
        {
            return Failure(IdentityTokenMigrationFailureCode.VerificationFailed);
        }

        bool legacyExists = await TableExistsAsync(connection, _names.LegacyTable, cancellationToken)
            .ConfigureAwait(false);
        if (!legacyExists)
        {
            return await AdvanceAndSaveAsync(
                checkpoint,
                IdentityTokenMigrationStage.PlaintextRemoved,
                checkpointStore,
                cancellationToken).ConfigureAwait(false);
        }

        if (!await LegacySchemaIsValidAsync(connection, _names.LegacyTable, cancellationToken)
                .ConfigureAwait(false) ||
            await CountRowsAsync(connection, _names.LegacyTable, cancellationToken).ConfigureAwait(false) !=
                checkpoint.ExpectedSourceRows)
        {
            return Failure(IdentityTokenMigrationFailureCode.VerificationFailed);
        }

        await SetExclusiveLockingAsync(connection, cancellationToken).ConfigureAwait(false);
        await using SqliteTransaction transaction = (SqliteTransaction)await connection
            .BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await using (SqliteCommand command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = $"DROP TABLE \"{_names.LegacyTable}\"";
            await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }

        if (!await ForeignKeysAreValidAsync(connection, transaction, cancellationToken).ConfigureAwait(false) ||
            !await IntegrityIsValidAsync(connection, transaction, cancellationToken).ConfigureAwait(false))
        {
            await transaction.RollbackAsync(CancellationToken.None).ConfigureAwait(false);
            return Failure(IdentityTokenMigrationFailureCode.VerificationFailed);
        }

        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        await connection.CloseAsync().ConfigureAwait(false);
        return await AdvanceAndSaveAsync(
            checkpoint,
            IdentityTokenMigrationStage.PlaintextRemoved,
            checkpointStore,
            cancellationToken).ConfigureAwait(false);
    }

    private static async Task<bool> TableExistsAsync(
        SqliteConnection connection,
        string table,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = $name";
        command.Parameters.AddWithValue("$name", table);
        return Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false),
            System.Globalization.CultureInfo.InvariantCulture) == 1;
    }

    private static async Task<long> CountRowsAsync(
        SqliteConnection connection,
        string table,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = $"SELECT COUNT(*) FROM \"{table}\"";
        return Convert.ToInt64(
            await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false),
            System.Globalization.CultureInfo.InvariantCulture);
    }

    private static async Task<bool> LegacySchemaIsValidAsync(
        SqliteConnection connection,
        string table,
        CancellationToken cancellationToken)
    {
        if (!await TableExistsAsync(connection, "AspNetUsers", cancellationToken).ConfigureAwait(false) ||
            !await TableExistsAsync(connection, table, cancellationToken).ConfigureAwait(false))
        {
            return false;
        }

        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = $"PRAGMA table_info({QuoteIdentifier(table)})";
        Dictionary<string, (bool NotNull, int PrimaryKeyOrder)> columns = new(StringComparer.Ordinal);
        await using (SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
        {
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                columns.Add(reader.GetString(1), (reader.GetInt32(3) == 1, reader.GetInt32(5)));
            }
        }

        return columns.Count == 4 &&
            columns.TryGetValue("UserId", out var userId) && userId == (true, 1) &&
            columns.TryGetValue("LoginProvider", out var provider) && provider == (true, 2) &&
            columns.TryGetValue("Name", out var name) && name == (true, 3) &&
            columns.TryGetValue("Value", out var value) && value == (false, 0) &&
            await HasExpectedUserForeignKeyAsync(connection, table, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<bool> ProtectedSchemaIsValidAsync(
        SqliteConnection connection,
        string table,
        CancellationToken cancellationToken)
    {
        if (!await TableExistsAsync(connection, "AspNetUsers", cancellationToken).ConfigureAwait(false) ||
            !await TableExistsAsync(connection, table, cancellationToken).ConfigureAwait(false))
        {
            return false;
        }

        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = $"PRAGMA table_info({QuoteIdentifier(table)})";
        Dictionary<string, (bool NotNull, int PrimaryKeyOrder)> columns = new(StringComparer.Ordinal);
        await using (SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
        {
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                columns.Add(reader.GetString(1), (reader.GetInt32(3) == 1, reader.GetInt32(5)));
            }
        }

        return columns.Count == 6 &&
            columns.TryGetValue("TokenId", out var tokenId) && tokenId == (true, 1) &&
            columns.TryGetValue("UserId", out var userId) && userId == (true, 0) &&
            columns.TryGetValue("LoginProvider", out var provider) && provider == (true, 0) &&
            columns.TryGetValue("Name", out var name) && name == (true, 0) &&
            columns.TryGetValue("Value", out var value) && value == (false, 0) &&
            columns.TryGetValue("RoutingHash", out var routingHash) && routingHash == (true, 0) &&
            await HasExpectedUserForeignKeyAsync(connection, table, cancellationToken).ConfigureAwait(false) &&
            await HasExpectedIndexAsync(connection, table, "RoutingHash", unique: true, cancellationToken)
                .ConfigureAwait(false) &&
            await HasExpectedIndexAsync(connection, table, "UserId", unique: false, cancellationToken)
                .ConfigureAwait(false);
    }

    private static async Task<bool> HasExpectedUserForeignKeyAsync(
        SqliteConnection connection,
        string table,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = $"PRAGMA foreign_key_list({QuoteIdentifier(table)})";
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            return false;
        }

        bool matches = string.Equals(reader.GetString(2), "AspNetUsers", StringComparison.Ordinal) &&
            string.Equals(reader.GetString(3), "UserId", StringComparison.Ordinal) &&
            string.Equals(reader.GetString(4), "Id", StringComparison.Ordinal) &&
            string.Equals(reader.GetString(6), "CASCADE", StringComparison.OrdinalIgnoreCase);
        return matches && !await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task<bool> HasExpectedIndexAsync(
        SqliteConnection connection,
        string table,
        string expectedColumn,
        bool unique,
        CancellationToken cancellationToken)
    {
        var indexes = new List<(string Name, bool Unique)>();
        await using (SqliteCommand command = connection.CreateCommand())
        {
            command.CommandText = $"PRAGMA index_list({QuoteIdentifier(table)})";
            await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                indexes.Add((reader.GetString(1), reader.GetInt32(2) != 0));
            }
        }

        foreach ((string indexName, bool isUnique) in indexes)
        {
            if (isUnique != unique)
            {
                continue;
            }

            await using SqliteCommand command = connection.CreateCommand();
            command.CommandText = $"PRAGMA index_info({QuoteIdentifier(indexName)})";
            await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false) &&
                string.Equals(reader.GetString(2), expectedColumn, StringComparison.Ordinal) &&
                !await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                return true;
            }
        }

        return false;
    }

    private static async Task RenameAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string source,
        string destination,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"ALTER TABLE \"{source}\" RENAME TO \"{destination}\"";
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task SetExclusiveLockingAsync(
        SqliteConnection connection,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "PRAGMA locking_mode=EXCLUSIVE";
        await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task<bool> ForeignKeysAreValidAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "PRAGMA foreign_key_check";
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        return !await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task<bool> IntegrityIsValidAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "PRAGMA integrity_check";
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ||
            !string.Equals(reader.GetString(0), "ok", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return !await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint>> AdvanceAndSaveAsync(
        IdentityTokenMigrationCheckpoint checkpoint,
        IdentityTokenMigrationStage nextStage,
        IIdentityTokenMigrationCheckpointStore checkpointStore,
        CancellationToken cancellationToken)
    {
        IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint> advanced =
            IdentityTokenMigrationStateMachine.Advance(
                checkpoint,
                nextStage,
                checkpoint.SourceRowsScanned,
                checkpoint.TargetRowsReady,
                checkpoint.TargetRowsVerified);
        if (advanced.IsSuccess)
        {
            await checkpointStore.SaveAsync(advanced.Value, cancellationToken).ConfigureAwait(false);
        }

        return advanced;
    }

    private static async ValueTask<IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint>> RecordRollbackAndSaveAsync(
        IdentityTokenMigrationCheckpoint checkpoint,
        IIdentityTokenMigrationCheckpointStore checkpointStore,
        CancellationToken cancellationToken)
    {
        IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint> rolledBack =
            IdentityTokenMigrationStateMachine.RecordTableSwapRollback(checkpoint);
        if (rolledBack.IsSuccess)
        {
            await checkpointStore.SaveAsync(rolledBack.Value, cancellationToken).ConfigureAwait(false);
        }

        return rolledBack;
    }

    private static string QuoteIdentifier(string identifier) =>
        '"' + identifier.Replace("\"", "\"\"", StringComparison.Ordinal) + '"';

    private static IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint> Failure(
        IdentityTokenMigrationFailureCode code) =>
        IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint>.Failure(code);
}
