using Microsoft.Data.Sqlite;

namespace Mrbr.Encryption.Data.Identity.Migration.Sqlite;

/// <summary>Durably persists non-secret migration progress in the SQLite database being migrated.</summary>
public sealed class SqliteIdentityTokenMigrationCheckpointStore :
    IIdentityTokenMigrationCheckpointStore,
    IIdentityTokenMigrationCheckpointReader
{
    private const string TableName = "__MrbrIdentityTokenMigrationCheckpoints";
    private readonly string _connectionString;

    /// <summary>Initializes a checkpoint store for the supplied SQLite database.</summary>
    public SqliteIdentityTokenMigrationCheckpointStore(string connectionString)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        _connectionString = connectionString;
    }

    /// <inheritdoc />
    public async ValueTask SaveAsync(
        IdentityTokenMigrationCheckpoint checkpoint,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);
        IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint> validation =
            IdentityTokenMigrationStateMachine.Restore(
                checkpoint.MigrationId,
                checkpoint.Stage,
                checkpoint.ExpectedSourceRows,
                checkpoint.SourceRowsScanned,
                checkpoint.TargetRowsReady,
                checkpoint.TargetRowsVerified,
                checkpoint.ProtectedWritesAccepted);
        if (!validation.IsSuccess)
        {
            throw new InvalidOperationException(
                $"The checkpoint is invalid and cannot be persisted. Failure code: {validation.FailureCode}.");
        }

        await using SqliteConnection connection = new(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await EnsureTableAsync(connection, cancellationToken).ConfigureAwait(false);
        await using SqliteTransaction transaction = (SqliteTransaction)await connection
            .BeginTransactionAsync(cancellationToken)
            .ConfigureAwait(false);

        IdentityTokenMigrationCheckpoint? current = await LoadCoreAsync(
            connection,
            transaction,
            checkpoint.MigrationId,
            cancellationToken).ConfigureAwait(false);
        if (current is not null)
        {
            ValidateMonotonicUpdate(current, checkpoint);
        }

        await using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            $"INSERT INTO \"{TableName}\" (" +
            "\"MigrationId\", \"Stage\", \"ExpectedSourceRows\", \"SourceRowsScanned\", " +
            "\"TargetRowsReady\", \"TargetRowsVerified\", \"ProtectedWritesAccepted\") " +
            "VALUES ($migrationId, $stage, $expected, $scanned, $ready, $verified, $writes) " +
            "ON CONFLICT(\"MigrationId\") DO UPDATE SET " +
            "\"Stage\" = excluded.\"Stage\", " +
            "\"SourceRowsScanned\" = excluded.\"SourceRowsScanned\", " +
            "\"TargetRowsReady\" = excluded.\"TargetRowsReady\", " +
            "\"TargetRowsVerified\" = excluded.\"TargetRowsVerified\", " +
            "\"ProtectedWritesAccepted\" = excluded.\"ProtectedWritesAccepted\";";
        command.Parameters.AddWithValue("$migrationId", checkpoint.MigrationId.ToString("D"));
        command.Parameters.AddWithValue("$stage", (int)checkpoint.Stage);
        command.Parameters.AddWithValue("$expected", checkpoint.ExpectedSourceRows);
        command.Parameters.AddWithValue("$scanned", checkpoint.SourceRowsScanned);
        command.Parameters.AddWithValue("$ready", checkpoint.TargetRowsReady);
        command.Parameters.AddWithValue("$verified", checkpoint.TargetRowsVerified);
        command.Parameters.AddWithValue("$writes", checkpoint.ProtectedWritesAccepted ? 1 : 0);
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask<IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint?>> LoadAsync(
        Guid migrationId,
        CancellationToken cancellationToken)
    {
        if (migrationId == Guid.Empty || migrationId.Version != 7)
        {
            return IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint?>.Failure(
                IdentityTokenMigrationFailureCode.InvalidMigrationIdentifier);
        }

        await using SqliteConnection connection = new(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        if (!await TableExistsAsync(connection, cancellationToken).ConfigureAwait(false))
        {
            return IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint?>.Success(null);
        }

        IdentityTokenMigrationCheckpoint? checkpoint = await LoadCoreAsync(
            connection,
            transaction: null,
            migrationId,
            cancellationToken).ConfigureAwait(false);
        return IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint?>.Success(checkpoint);
    }

    /// <summary>Loads the sole unfinished migration without creating checkpoint storage.</summary>
    public async ValueTask<IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint?>> LoadActiveAsync(
        CancellationToken cancellationToken = default)
    {
        await using SqliteConnection connection = new(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        if (!await TableExistsAsync(connection, cancellationToken).ConfigureAwait(false))
        {
            return IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint?>.Success(null);
        }

        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            $"SELECT \"MigrationId\" FROM \"{TableName}\" " +
            "WHERE \"Stage\" NOT IN ($removed, $rolledBack) LIMIT 2;";
        command.Parameters.AddWithValue("$removed", (int)IdentityTokenMigrationStage.PlaintextRemoved);
        command.Parameters.AddWithValue("$rolledBack", (int)IdentityTokenMigrationStage.RolledBack);
        var migrationIds = new List<Guid>(2);
        await using (SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
        {
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                if (!Guid.TryParseExact(reader.GetString(0), "D", out Guid migrationId) || migrationId.Version != 7)
                {
                    throw new InvalidDataException("An active migration checkpoint identifier is invalid.");
                }

                migrationIds.Add(migrationId);
            }
        }

        if (migrationIds.Count > 1)
        {
            throw new InvalidDataException("More than one unfinished Identity token migration exists.");
        }

        if (migrationIds.Count == 0)
        {
            return IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint?>.Success(null);
        }

        IdentityTokenMigrationCheckpoint? checkpoint = await LoadCoreAsync(
            connection,
            transaction: null,
            migrationIds[0],
            cancellationToken).ConfigureAwait(false);
        return IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint?>.Success(checkpoint);
    }

    private static async ValueTask<bool> TableExistsAsync(
        SqliteConnection connection,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = $name;";
        command.Parameters.AddWithValue("$name", TableName);
        object? value = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        return Convert.ToInt64(value, System.Globalization.CultureInfo.InvariantCulture) == 1;
    }

    private static async ValueTask EnsureTableAsync(
        SqliteConnection connection,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            $"CREATE TABLE IF NOT EXISTS \"{TableName}\" (" +
            "\"MigrationId\" TEXT NOT NULL PRIMARY KEY, " +
            "\"Stage\" INTEGER NOT NULL, " +
            "\"ExpectedSourceRows\" INTEGER NOT NULL, " +
            "\"SourceRowsScanned\" INTEGER NOT NULL, " +
            "\"TargetRowsReady\" INTEGER NOT NULL, " +
            "\"TargetRowsVerified\" INTEGER NOT NULL, " +
            "\"ProtectedWritesAccepted\" INTEGER NOT NULL);";
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<IdentityTokenMigrationCheckpoint?> LoadCoreAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        Guid migrationId,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            $"SELECT \"Stage\", \"ExpectedSourceRows\", \"SourceRowsScanned\", " +
            "\"TargetRowsReady\", \"TargetRowsVerified\", \"ProtectedWritesAccepted\" " +
            $"FROM \"{TableName}\" WHERE \"MigrationId\" = $migrationId;";
        command.Parameters.AddWithValue("$migrationId", migrationId.ToString("D"));
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint> restored =
            IdentityTokenMigrationStateMachine.Restore(
                migrationId,
                (IdentityTokenMigrationStage)reader.GetInt32(0),
                reader.GetInt64(1),
                reader.GetInt64(2),
                reader.GetInt64(3),
                reader.GetInt64(4),
                reader.GetInt64(5) != 0);
        if (!restored.IsSuccess)
        {
            throw new InvalidDataException(
                $"The durable migration checkpoint is invalid. Failure code: {restored.FailureCode}.");
        }

        return restored.Value;
    }

    private static void ValidateMonotonicUpdate(
        IdentityTokenMigrationCheckpoint current,
        IdentityTokenMigrationCheckpoint next)
    {
        bool rollbackTransition =
            current.Stage is IdentityTokenMigrationStage.CutoverComplete or IdentityTokenMigrationStage.RuntimeVerified &&
            next.Stage == IdentityTokenMigrationStage.RolledBack;
        bool stageIsMonotonic =
            next.Stage == current.Stage ||
            (int)next.Stage == (int)current.Stage + 1 ||
            rollbackTransition;
        if (current.ExpectedSourceRows != next.ExpectedSourceRows ||
            !stageIsMonotonic ||
            current.Stage == IdentityTokenMigrationStage.RolledBack && next.Stage != current.Stage ||
            next.SourceRowsScanned < current.SourceRowsScanned ||
            next.TargetRowsReady < current.TargetRowsReady ||
            next.TargetRowsVerified < current.TargetRowsVerified ||
            current.ProtectedWritesAccepted && !next.ProtectedWritesAccepted)
        {
            throw new InvalidOperationException("A durable migration checkpoint cannot move backwards or skip stages.");
        }
    }
}
