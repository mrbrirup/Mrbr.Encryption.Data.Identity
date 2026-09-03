using Npgsql;

namespace Mrbr.Encryption.Data.Identity.Migration.PostgreSql;

/// <summary>Persists non-secret migration progress in the PostgreSQL database being migrated.</summary>
public sealed class PostgreSqlIdentityTokenMigrationCheckpointStore :
    IIdentityTokenMigrationCheckpointStore,
    IIdentityTokenMigrationCheckpointReader
{
    private const string TableName = "__MrbrIdentityTokenMigrationCheckpoints";
    private const long AdvisoryLockKey = 0x4D_52_42_52_49_54_4D;
    private readonly string _connectionString;

    public PostgreSqlIdentityTokenMigrationCheckpointStore(string connectionString)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        _connectionString = connectionString;
    }

    public async ValueTask SaveAsync(IdentityTokenMigrationCheckpoint checkpoint, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);
        IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint> validation =
            IdentityTokenMigrationStateMachine.Restore(
                checkpoint.MigrationId, checkpoint.Stage, checkpoint.ExpectedSourceRows,
                checkpoint.SourceRowsScanned, checkpoint.TargetRowsReady, checkpoint.TargetRowsVerified,
                checkpoint.ProtectedWritesAccepted);
        if (!validation.IsSuccess)
        {
            throw new InvalidOperationException(
                $"The checkpoint is invalid and cannot be persisted. Failure code: {validation.FailureCode}.");
        }

        await using NpgsqlConnection connection = new(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await EnsureTableAsync(connection, cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken)
            .ConfigureAwait(false);
        await AcquireLockAsync(connection, transaction, cancellationToken).ConfigureAwait(false);
        IdentityTokenMigrationCheckpoint? current = await LoadCoreAsync(
            connection, transaction, checkpoint.MigrationId, cancellationToken).ConfigureAwait(false);
        if (current is not null) ValidateMonotonicUpdate(current, checkpoint);

        await using NpgsqlCommand command = new(
            $"INSERT INTO \"{TableName}\" (\"MigrationId\", \"Stage\", \"ExpectedSourceRows\", " +
            "\"SourceRowsScanned\", \"TargetRowsReady\", \"TargetRowsVerified\", \"ProtectedWritesAccepted\") " +
            "VALUES (@id, @stage, @expected, @scanned, @ready, @verified, @writes) " +
            "ON CONFLICT (\"MigrationId\") DO UPDATE SET \"Stage\" = EXCLUDED.\"Stage\", " +
            "\"SourceRowsScanned\" = EXCLUDED.\"SourceRowsScanned\", " +
            "\"TargetRowsReady\" = EXCLUDED.\"TargetRowsReady\", " +
            "\"TargetRowsVerified\" = EXCLUDED.\"TargetRowsVerified\", " +
            "\"ProtectedWritesAccepted\" = EXCLUDED.\"ProtectedWritesAccepted\"",
            connection, transaction);
        command.Parameters.AddWithValue("id", checkpoint.MigrationId);
        command.Parameters.AddWithValue("stage", (short)checkpoint.Stage);
        command.Parameters.AddWithValue("expected", checkpoint.ExpectedSourceRows);
        command.Parameters.AddWithValue("scanned", checkpoint.SourceRowsScanned);
        command.Parameters.AddWithValue("ready", checkpoint.TargetRowsReady);
        command.Parameters.AddWithValue("verified", checkpoint.TargetRowsVerified);
        command.Parameters.AddWithValue("writes", checkpoint.ProtectedWritesAccepted);
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint?>> LoadAsync(
        Guid migrationId, CancellationToken cancellationToken)
    {
        if (migrationId == Guid.Empty || migrationId.Version != 7)
            return IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint?>.Failure(
                IdentityTokenMigrationFailureCode.InvalidMigrationIdentifier);
        await using NpgsqlConnection connection = new(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        if (!await TableExistsAsync(connection, cancellationToken).ConfigureAwait(false))
            return IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint?>.Success(null);
        return IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint?>.Success(
            await LoadCoreAsync(connection, null, migrationId, cancellationToken).ConfigureAwait(false));
    }

    public async ValueTask<IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint?>> LoadActiveAsync(
        CancellationToken cancellationToken = default)
    {
        await using NpgsqlConnection connection = new(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        if (!await TableExistsAsync(connection, cancellationToken).ConfigureAwait(false))
            return IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint?>.Success(null);
        await using NpgsqlCommand command = new(
            $"SELECT \"MigrationId\" FROM \"{TableName}\" WHERE \"Stage\" NOT IN (@removed, @rolledBack) LIMIT 2",
            connection);
        command.Parameters.AddWithValue("removed", (short)IdentityTokenMigrationStage.PlaintextRemoved);
        command.Parameters.AddWithValue("rolledBack", (short)IdentityTokenMigrationStage.RolledBack);
        var ids = new List<Guid>(2);
        await using (NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) ids.Add(reader.GetGuid(0));
        if (ids.Count > 1) throw new InvalidDataException("More than one unfinished Identity token migration exists.");
        if (ids.Count == 0) return IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint?>.Success(null);
        return IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint?>.Success(
            await LoadCoreAsync(connection, null, ids[0], cancellationToken).ConfigureAwait(false));
    }

    private static async Task EnsureTableAsync(NpgsqlConnection connection, CancellationToken cancellationToken)
    {
        await using NpgsqlCommand command = new(
            $"CREATE TABLE IF NOT EXISTS \"{TableName}\" (" +
            "\"MigrationId\" uuid NOT NULL PRIMARY KEY, \"Stage\" smallint NOT NULL, " +
            "\"ExpectedSourceRows\" bigint NOT NULL, \"SourceRowsScanned\" bigint NOT NULL, " +
            "\"TargetRowsReady\" bigint NOT NULL, \"TargetRowsVerified\" bigint NOT NULL, " +
            "\"ProtectedWritesAccepted\" boolean NOT NULL)", connection);
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task<bool> TableExistsAsync(NpgsqlConnection connection, CancellationToken cancellationToken)
    {
        await using NpgsqlCommand command = new(
            "SELECT to_regclass(format('%I.%I', current_schema(), @table)) IS NOT NULL", connection);
        command.Parameters.AddWithValue("table", TableName);
        return (bool)(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) ?? false);
    }

    private static async Task AcquireLockAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction, CancellationToken cancellationToken)
    {
        await using NpgsqlCommand command = new("SELECT pg_advisory_xact_lock(@key)", connection, transaction);
        command.Parameters.AddWithValue("key", AdvisoryLockKey);
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task<IdentityTokenMigrationCheckpoint?> LoadCoreAsync(
        NpgsqlConnection connection, NpgsqlTransaction? transaction, Guid migrationId,
        CancellationToken cancellationToken)
    {
        await using NpgsqlCommand command = new(
            $"SELECT \"Stage\", \"ExpectedSourceRows\", \"SourceRowsScanned\", \"TargetRowsReady\", " +
            $"\"TargetRowsVerified\", \"ProtectedWritesAccepted\" FROM \"{TableName}\" WHERE \"MigrationId\" = @id",
            connection, transaction);
        command.Parameters.AddWithValue("id", migrationId);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) return null;
        IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint> restored = IdentityTokenMigrationStateMachine.Restore(
            migrationId, (IdentityTokenMigrationStage)reader.GetInt16(0), reader.GetInt64(1), reader.GetInt64(2),
            reader.GetInt64(3), reader.GetInt64(4), reader.GetBoolean(5));
        if (!restored.IsSuccess)
            throw new InvalidDataException(
                $"The durable migration checkpoint is invalid. Failure code: {restored.FailureCode}.");
        return restored.Value;
    }

    private static void ValidateMonotonicUpdate(
        IdentityTokenMigrationCheckpoint current, IdentityTokenMigrationCheckpoint next)
    {
        bool rollback = current.Stage is IdentityTokenMigrationStage.CutoverComplete or
            IdentityTokenMigrationStage.RuntimeVerified && next.Stage == IdentityTokenMigrationStage.RolledBack;
        bool stageMonotonic = next.Stage == current.Stage || (int)next.Stage == (int)current.Stage + 1 || rollback;
        if (current.ExpectedSourceRows != next.ExpectedSourceRows || !stageMonotonic ||
            current.Stage == IdentityTokenMigrationStage.RolledBack && next.Stage != current.Stage ||
            next.SourceRowsScanned < current.SourceRowsScanned || next.TargetRowsReady < current.TargetRowsReady ||
            next.TargetRowsVerified < current.TargetRowsVerified ||
            current.ProtectedWritesAccepted && !next.ProtectedWritesAccepted)
            throw new InvalidOperationException("A durable migration checkpoint cannot move backwards or skip stages.");
    }
}
