using Npgsql;

namespace Mrbr.Encryption.Data.Identity.Migration.PostgreSql;

/// <summary>Creates and transactionally swaps PostgreSQL token tables for one offline migration.</summary>
public sealed class PostgreSqlIdentityTokenMigrationSchemaExecutor
{
    private readonly string _connectionString;
    private readonly PostgreSqlIdentityTokenMigrationNames _names;

    public PostgreSqlIdentityTokenMigrationSchemaExecutor(string connectionString, Guid migrationId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        _connectionString = new NpgsqlConnectionStringBuilder(connectionString) { Pooling = false }.ConnectionString;
        _names = new PostgreSqlIdentityTokenMigrationNames(migrationId);
    }

    public async ValueTask<IdentityTokenMigrationResult<long>> ValidatePreflightAsync(
        CancellationToken cancellationToken = default)
    {
        await using NpgsqlConnection connection = new(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        if (!await LegacySchemaIsValidAsync(connection, null, _names.ApplicationTable, cancellationToken)
                .ConfigureAwait(false))
            return Failure<long>(IdentityTokenMigrationFailureCode.InvalidSourceRow);
        if (await MigrationTableExistsAsync(connection, cancellationToken).ConfigureAwait(false))
            return Failure<long>(IdentityTokenMigrationFailureCode.InvalidStageTransition);
        return IdentityTokenMigrationResult<long>.Success(
            await CountRowsAsync(connection, null, _names.ApplicationTable, cancellationToken).ConfigureAwait(false));
    }

    public async ValueTask<IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint>> CreateShadowSchemaAsync(
        IdentityTokenMigrationCheckpoint checkpoint,
        IIdentityTokenMigrationCheckpointStore checkpointStore,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);
        ArgumentNullException.ThrowIfNull(checkpointStore);
        if (checkpoint.Stage != IdentityTokenMigrationStage.PreflightPassed)
            return Failure<IdentityTokenMigrationCheckpoint>(IdentityTokenMigrationFailureCode.InvalidStageTransition);
        await using NpgsqlConnection connection = new(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        if (!await LegacySchemaIsValidAsync(connection, null, _names.ApplicationTable, cancellationToken)
                .ConfigureAwait(false))
            return Failure<IdentityTokenMigrationCheckpoint>(IdentityTokenMigrationFailureCode.InvalidSourceRow);
        if (await CountRowsAsync(connection, null, _names.ApplicationTable, cancellationToken).ConfigureAwait(false) !=
            checkpoint.ExpectedSourceRows)
            return Failure<IdentityTokenMigrationCheckpoint>(IdentityTokenMigrationFailureCode.SourceChanged);
        bool shadowExists = await TableExistsAsync(connection, null, _names.ShadowTable, cancellationToken)
            .ConfigureAwait(false);
        if (await TableExistsAsync(connection, null, _names.LegacyTable, cancellationToken).ConfigureAwait(false))
            return Failure<IdentityTokenMigrationCheckpoint>(IdentityTokenMigrationFailureCode.InvalidStageTransition);
        if (shadowExists)
        {
            if (!await ProtectedSchemaIsValidAsync(connection, null, _names.ShadowTable, cancellationToken)
                    .ConfigureAwait(false) ||
                await CountRowsAsync(connection, null, _names.ShadowTable, cancellationToken).ConfigureAwait(false) != 0)
                return Failure<IdentityTokenMigrationCheckpoint>(IdentityTokenMigrationFailureCode.InvalidStageTransition);
            return await AdvanceAndSaveAsync(
                checkpoint, IdentityTokenMigrationStage.ShadowSchemaCreated, checkpointStore, cancellationToken)
                .ConfigureAwait(false);
        }

        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken)
            .ConfigureAwait(false);
        await using NpgsqlCommand command = new(
            $"CREATE TABLE {Quote(_names.ShadowTable)} (" +
            "\"TokenId\" uuid NOT NULL CONSTRAINT \"PK_MrbrProtectedUserTokens\" PRIMARY KEY, " +
            "\"UserId\" text NOT NULL, \"LoginProvider\" text NOT NULL, \"Name\" text NOT NULL, " +
            "\"Value\" text NULL, \"RoutingHash\" character varying(64) NOT NULL, " +
            "CONSTRAINT \"FK_MrbrProtectedUserTokens_AspNetUsers_UserId\" FOREIGN KEY (\"UserId\") " +
            "REFERENCES \"AspNetUsers\" (\"Id\") ON DELETE CASCADE);" +
            $"CREATE UNIQUE INDEX {Quote(_names.ShadowRouteIndex)} ON {Quote(_names.ShadowTable)} (\"RoutingHash\");" +
            $"CREATE INDEX {Quote(_names.ShadowUserIndex)} ON {Quote(_names.ShadowTable)} (\"UserId\");",
            connection, transaction);
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return await AdvanceAndSaveAsync(
            checkpoint, IdentityTokenMigrationStage.ShadowSchemaCreated, checkpointStore, cancellationToken)
            .ConfigureAwait(false);
    }

    public async ValueTask<IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint>> CutoverAsync(
        IdentityTokenMigrationCheckpoint checkpoint,
        IIdentityTokenMigrationCheckpointStore checkpointStore,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);
        ArgumentNullException.ThrowIfNull(checkpointStore);
        if (checkpoint.Stage != IdentityTokenMigrationStage.Verified)
            return Failure<IdentityTokenMigrationCheckpoint>(IdentityTokenMigrationFailureCode.InvalidStageTransition);
        await using NpgsqlConnection connection = new(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        bool app = await TableExistsAsync(connection, null, _names.ApplicationTable, cancellationToken).ConfigureAwait(false);
        bool shadow = await TableExistsAsync(connection, null, _names.ShadowTable, cancellationToken).ConfigureAwait(false);
        bool legacy = await TableExistsAsync(connection, null, _names.LegacyTable, cancellationToken).ConfigureAwait(false);
        if (app && !shadow && legacy &&
            await ProtectedSchemaIsValidAsync(connection, null, _names.ApplicationTable, cancellationToken).ConfigureAwait(false) &&
            await LegacySchemaIsValidAsync(connection, null, _names.LegacyTable, cancellationToken).ConfigureAwait(false) &&
            await CountsMatchAsync(connection, null, checkpoint, cancellationToken).ConfigureAwait(false))
            return await AdvanceAndSaveAsync(
                checkpoint, IdentityTokenMigrationStage.CutoverComplete, checkpointStore, cancellationToken)
                .ConfigureAwait(false);
        if (!app || !shadow || legacy ||
            !await LegacySchemaIsValidAsync(connection, null, _names.ApplicationTable, cancellationToken).ConfigureAwait(false) ||
            !await ProtectedSchemaIsValidAsync(connection, null, _names.ShadowTable, cancellationToken).ConfigureAwait(false) ||
            await CountRowsAsync(connection, null, _names.ApplicationTable, cancellationToken).ConfigureAwait(false) != checkpoint.ExpectedSourceRows ||
            await CountRowsAsync(connection, null, _names.ShadowTable, cancellationToken).ConfigureAwait(false) != checkpoint.ExpectedSourceRows)
            return Failure<IdentityTokenMigrationCheckpoint>(IdentityTokenMigrationFailureCode.VerificationFailed);

        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await ExecuteAsync(connection, transaction,
            $"LOCK TABLE {Quote(_names.ApplicationTable)}, {Quote(_names.ShadowTable)} IN ACCESS EXCLUSIVE MODE",
            cancellationToken).ConfigureAwait(false);
        await RenameTableAsync(connection, transaction, _names.ApplicationTable, _names.LegacyTable, cancellationToken).ConfigureAwait(false);
        await RenameTableAsync(connection, transaction, _names.ShadowTable, _names.ApplicationTable, cancellationToken).ConfigureAwait(false);
        await RenameIndexAsync(connection, transaction, _names.ShadowRouteIndex, _names.FinalRouteIndex, cancellationToken).ConfigureAwait(false);
        await RenameIndexAsync(connection, transaction, _names.ShadowUserIndex, _names.FinalUserIndex, cancellationToken).ConfigureAwait(false);
        if (!await ProtectedSchemaIsValidAsync(connection, transaction, _names.ApplicationTable, cancellationToken).ConfigureAwait(false) ||
            !await LegacySchemaIsValidAsync(connection, transaction, _names.LegacyTable, cancellationToken).ConfigureAwait(false) ||
            !await CountsMatchAsync(connection, transaction, checkpoint, cancellationToken).ConfigureAwait(false))
        {
            await transaction.RollbackAsync(CancellationToken.None).ConfigureAwait(false);
            return Failure<IdentityTokenMigrationCheckpoint>(IdentityTokenMigrationFailureCode.VerificationFailed);
        }
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return await AdvanceAndSaveAsync(
            checkpoint, IdentityTokenMigrationStage.CutoverComplete, checkpointStore, cancellationToken)
            .ConfigureAwait(false);
    }

    public async ValueTask<IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint>> RollbackCutoverAsync(
        IdentityTokenMigrationCheckpoint checkpoint,
        IIdentityTokenMigrationCheckpointStore checkpointStore,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);
        ArgumentNullException.ThrowIfNull(checkpointStore);
        IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint> allowed =
            IdentityTokenMigrationStateMachine.ValidateTableSwapRollback(checkpoint);
        if (!allowed.IsSuccess) return allowed;
        await using NpgsqlConnection connection = new(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        bool app = await TableExistsAsync(connection, null, _names.ApplicationTable, cancellationToken).ConfigureAwait(false);
        bool shadow = await TableExistsAsync(connection, null, _names.ShadowTable, cancellationToken).ConfigureAwait(false);
        bool legacy = await TableExistsAsync(connection, null, _names.LegacyTable, cancellationToken).ConfigureAwait(false);
        if (app && shadow && !legacy &&
            await LegacySchemaIsValidAsync(connection, null, _names.ApplicationTable, cancellationToken).ConfigureAwait(false) &&
            await ProtectedSchemaIsValidAsync(connection, null, _names.ShadowTable, cancellationToken).ConfigureAwait(false))
            return await RollbackAndSaveAsync(checkpoint, checkpointStore, cancellationToken).ConfigureAwait(false);
        if (!app || shadow || !legacy ||
            !await ProtectedSchemaIsValidAsync(connection, null, _names.ApplicationTable, cancellationToken).ConfigureAwait(false) ||
            !await LegacySchemaIsValidAsync(connection, null, _names.LegacyTable, cancellationToken).ConfigureAwait(false))
            return Failure<IdentityTokenMigrationCheckpoint>(IdentityTokenMigrationFailureCode.VerificationFailed);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await ExecuteAsync(connection, transaction,
            $"LOCK TABLE {Quote(_names.ApplicationTable)}, {Quote(_names.LegacyTable)} IN ACCESS EXCLUSIVE MODE",
            cancellationToken).ConfigureAwait(false);
        await RenameTableAsync(connection, transaction, _names.ApplicationTable, _names.ShadowTable, cancellationToken).ConfigureAwait(false);
        await RenameTableAsync(connection, transaction, _names.LegacyTable, _names.ApplicationTable, cancellationToken).ConfigureAwait(false);
        await RenameIndexAsync(connection, transaction, _names.FinalRouteIndex, _names.ShadowRouteIndex, cancellationToken).ConfigureAwait(false);
        await RenameIndexAsync(connection, transaction, _names.FinalUserIndex, _names.ShadowUserIndex, cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return await RollbackAndSaveAsync(checkpoint, checkpointStore, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint>> RemoveRetainedPlaintextAsync(
        IdentityTokenMigrationCheckpoint checkpoint,
        IdentityTokenMigrationPlaintextRemovalApproval approval,
        IIdentityTokenMigrationCheckpointStore checkpointStore,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);
        ArgumentNullException.ThrowIfNull(approval);
        ArgumentNullException.ThrowIfNull(checkpointStore);
        if (checkpoint.Stage != IdentityTokenMigrationStage.RuntimeVerified || !checkpoint.ProtectedWritesAccepted)
            return Failure<IdentityTokenMigrationCheckpoint>(IdentityTokenMigrationFailureCode.InvalidStageTransition);
        if (!approval.IsApprovedFor(checkpoint.MigrationId))
            return Failure<IdentityTokenMigrationCheckpoint>(IdentityTokenMigrationFailureCode.OperatorApprovalRequired);
        await using NpgsqlConnection connection = new(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        if (!await ProtectedSchemaIsValidAsync(connection, null, _names.ApplicationTable, cancellationToken).ConfigureAwait(false))
            return Failure<IdentityTokenMigrationCheckpoint>(IdentityTokenMigrationFailureCode.VerificationFailed);
        if (!await TableExistsAsync(connection, null, _names.LegacyTable, cancellationToken).ConfigureAwait(false))
            return await AdvanceAndSaveAsync(
                checkpoint, IdentityTokenMigrationStage.PlaintextRemoved, checkpointStore, cancellationToken)
                .ConfigureAwait(false);
        if (!await LegacySchemaIsValidAsync(connection, null, _names.LegacyTable, cancellationToken).ConfigureAwait(false) ||
            await CountRowsAsync(connection, null, _names.LegacyTable, cancellationToken).ConfigureAwait(false) != checkpoint.ExpectedSourceRows)
            return Failure<IdentityTokenMigrationCheckpoint>(IdentityTokenMigrationFailureCode.VerificationFailed);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await ExecuteAsync(connection, transaction,
            $"LOCK TABLE {Quote(_names.ApplicationTable)}, {Quote(_names.LegacyTable)} IN ACCESS EXCLUSIVE MODE",
            cancellationToken).ConfigureAwait(false);
        await ExecuteAsync(connection, transaction, $"DROP TABLE {Quote(_names.LegacyTable)}", cancellationToken)
            .ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return await AdvanceAndSaveAsync(
            checkpoint, IdentityTokenMigrationStage.PlaintextRemoved, checkpointStore, cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task<bool> CountsMatchAsync(
        NpgsqlConnection connection, NpgsqlTransaction? transaction,
        IdentityTokenMigrationCheckpoint checkpoint, CancellationToken cancellationToken) =>
        await CountRowsAsync(connection, transaction, _names.ApplicationTable, cancellationToken).ConfigureAwait(false) == checkpoint.ExpectedSourceRows &&
        await CountRowsAsync(connection, transaction, _names.LegacyTable, cancellationToken).ConfigureAwait(false) == checkpoint.ExpectedSourceRows;

    private static async Task<bool> LegacySchemaIsValidAsync(
        NpgsqlConnection connection, NpgsqlTransaction? transaction, string table, CancellationToken cancellationToken)
    {
        Dictionary<string, (string Type, bool Nullable)> columns = await ColumnsAsync(connection, transaction, table, cancellationToken).ConfigureAwait(false);
        return columns.Count == 4 && IsText(columns, "UserId", false) && IsText(columns, "LoginProvider", false) &&
            IsText(columns, "Name", false) && IsText(columns, "Value", true) &&
            await PrimaryKeyMatchesAsync(connection, transaction, table, ["UserId", "LoginProvider", "Name"], cancellationToken).ConfigureAwait(false) &&
            await UserForeignKeyIsValidAsync(connection, transaction, table, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<bool> ProtectedSchemaIsValidAsync(
        NpgsqlConnection connection, NpgsqlTransaction? transaction, string table, CancellationToken cancellationToken)
    {
        Dictionary<string, (string Type, bool Nullable)> columns = await ColumnsAsync(connection, transaction, table, cancellationToken).ConfigureAwait(false);
        return columns.Count == 6 && columns.TryGetValue("TokenId", out var token) && token == ("uuid", false) &&
            IsText(columns, "UserId", false) && IsText(columns, "LoginProvider", false) && IsText(columns, "Name", false) &&
            IsText(columns, "Value", true) && IsText(columns, "RoutingHash", false) &&
            await PrimaryKeyMatchesAsync(connection, transaction, table, ["TokenId"], cancellationToken).ConfigureAwait(false) &&
            await UserForeignKeyIsValidAsync(connection, transaction, table, cancellationToken).ConfigureAwait(false) &&
            await HasIndexAsync(connection, transaction, table, "RoutingHash", true, cancellationToken).ConfigureAwait(false) &&
            await HasIndexAsync(connection, transaction, table, "UserId", false, cancellationToken).ConfigureAwait(false);
    }

    private static bool IsText(Dictionary<string, (string Type, bool Nullable)> columns, string name, bool nullable) =>
        columns.TryGetValue(name, out var value) && value.Nullable == nullable &&
        value.Type is "text" or "character varying";

    private static async Task<Dictionary<string, (string Type, bool Nullable)>> ColumnsAsync(
        NpgsqlConnection connection, NpgsqlTransaction? transaction, string table, CancellationToken cancellationToken)
    {
        await using NpgsqlCommand command = new(
            "SELECT column_name, data_type, is_nullable FROM information_schema.columns " +
            "WHERE table_schema = current_schema() AND table_name = @table", connection, transaction);
        command.Parameters.AddWithValue("table", table);
        var columns = new Dictionary<string, (string, bool)>(StringComparer.Ordinal);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            columns.Add(reader.GetString(0), (reader.GetString(1), reader.GetString(2) == "YES"));
        return columns;
    }

    private static async Task<bool> PrimaryKeyMatchesAsync(
        NpgsqlConnection connection, NpgsqlTransaction? transaction, string table,
        string[] expected, CancellationToken cancellationToken)
    {
        await using NpgsqlCommand command = new(
            "SELECT array_agg(a.attname ORDER BY k.ordinality) FROM pg_constraint c " +
            "CROSS JOIN LATERAL unnest(c.conkey) WITH ORDINALITY AS k(attnum, ordinality) " +
            "JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum " +
            "WHERE c.contype = 'p' AND c.conrelid = to_regclass(format('%I.%I', current_schema(), @table))",
            connection, transaction);
        command.Parameters.AddWithValue("table", table);
        object? value = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        return value is string[] actual && actual.SequenceEqual(expected, StringComparer.Ordinal);
    }

    private static async Task<bool> UserForeignKeyIsValidAsync(
        NpgsqlConnection connection, NpgsqlTransaction? transaction, string table, CancellationToken cancellationToken)
    {
        await using NpgsqlCommand command = new(
            "SELECT COUNT(*) = 1 FROM pg_constraint c WHERE c.contype = 'f' AND c.convalidated " +
            "AND c.conrelid = to_regclass(format('%I.%I', current_schema(), @table)) " +
            "AND c.confrelid = to_regclass(format('%I.%I', current_schema(), 'AspNetUsers')) " +
            "AND c.confdeltype = 'c' AND array_length(c.conkey, 1) = 1 AND array_length(c.confkey, 1) = 1 " +
            "AND (SELECT attname FROM pg_attribute WHERE attrelid = c.conrelid AND attnum = c.conkey[1]) = 'UserId' " +
            "AND (SELECT attname FROM pg_attribute WHERE attrelid = c.confrelid AND attnum = c.confkey[1]) = 'Id'",
            connection, transaction);
        command.Parameters.AddWithValue("table", table);
        return (bool)(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) ?? false);
    }

    private static async Task<bool> HasIndexAsync(
        NpgsqlConnection connection, NpgsqlTransaction? transaction, string table,
        string column, bool unique, CancellationToken cancellationToken)
    {
        await using NpgsqlCommand command = new(
            "SELECT EXISTS (SELECT 1 FROM pg_index i JOIN pg_attribute a " +
            "ON a.attrelid = i.indrelid AND a.attnum = i.indkey[0] " +
            "WHERE i.indrelid = to_regclass(format('%I.%I', current_schema(), @table)) " +
            "AND i.indisvalid AND i.indisready AND i.indnatts = 1 AND i.indisunique = @unique AND a.attname = @column)",
            connection, transaction);
        command.Parameters.AddWithValue("table", table);
        command.Parameters.AddWithValue("unique", unique);
        command.Parameters.AddWithValue("column", column);
        return (bool)(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) ?? false);
    }

    private static async Task<bool> MigrationTableExistsAsync(NpgsqlConnection connection, CancellationToken cancellationToken)
    {
        await using NpgsqlCommand command = new(
            "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = current_schema() " +
            "AND (table_name LIKE 'AspNetUserTokens\\_MrbrProtected\\_%' ESCAPE '\\' " +
            "OR table_name LIKE 'AspNetUserTokens\\_MrbrLegacy\\_%' ESCAPE '\\'))", connection);
        return (bool)(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) ?? false);
    }

    private static async Task<bool> TableExistsAsync(
        NpgsqlConnection connection, NpgsqlTransaction? transaction, string table, CancellationToken cancellationToken)
    {
        await using NpgsqlCommand command = new(
            "SELECT to_regclass(format('%I.%I', current_schema(), @table)) IS NOT NULL", connection, transaction);
        command.Parameters.AddWithValue("table", table);
        return (bool)(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) ?? false);
    }

    private static async Task<long> CountRowsAsync(
        NpgsqlConnection connection, NpgsqlTransaction? transaction, string table, CancellationToken cancellationToken)
    {
        await using NpgsqlCommand command = new($"SELECT COUNT(*) FROM {Quote(table)}", connection, transaction);
        return Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false),
            System.Globalization.CultureInfo.InvariantCulture);
    }

    private static Task RenameTableAsync(NpgsqlConnection c, NpgsqlTransaction t, string source, string target, CancellationToken ct) =>
        ExecuteAsync(c, t, $"ALTER TABLE {Quote(source)} RENAME TO {Quote(target)}", ct);
    private static Task RenameIndexAsync(NpgsqlConnection c, NpgsqlTransaction t, string source, string target, CancellationToken ct) =>
        ExecuteAsync(c, t, $"ALTER INDEX {Quote(source)} RENAME TO {Quote(target)}", ct);
    private static async Task ExecuteAsync(NpgsqlConnection c, NpgsqlTransaction t, string sql, CancellationToken ct)
    {
        await using NpgsqlCommand command = new(sql, c, t);
        await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    private static async ValueTask<IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint>> AdvanceAndSaveAsync(
        IdentityTokenMigrationCheckpoint checkpoint, IdentityTokenMigrationStage stage,
        IIdentityTokenMigrationCheckpointStore store, CancellationToken cancellationToken)
    {
        IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint> advanced = IdentityTokenMigrationStateMachine.Advance(
            checkpoint, stage, checkpoint.SourceRowsScanned, checkpoint.TargetRowsReady, checkpoint.TargetRowsVerified);
        if (advanced.IsSuccess) await store.SaveAsync(advanced.Value, cancellationToken).ConfigureAwait(false);
        return advanced;
    }

    private static async ValueTask<IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint>> RollbackAndSaveAsync(
        IdentityTokenMigrationCheckpoint checkpoint, IIdentityTokenMigrationCheckpointStore store,
        CancellationToken cancellationToken)
    {
        IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint> rolled =
            IdentityTokenMigrationStateMachine.RecordTableSwapRollback(checkpoint);
        if (rolled.IsSuccess) await store.SaveAsync(rolled.Value, cancellationToken).ConfigureAwait(false);
        return rolled;
    }

    private static IdentityTokenMigrationResult<T> Failure<T>(IdentityTokenMigrationFailureCode code) =>
        IdentityTokenMigrationResult<T>.Failure(code);
    private static string Quote(string identifier) => '"' + identifier.Replace("\"", "\"\"", StringComparison.Ordinal) + '"';
}
