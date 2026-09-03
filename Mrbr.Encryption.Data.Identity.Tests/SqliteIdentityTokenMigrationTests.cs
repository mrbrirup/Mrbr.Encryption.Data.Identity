using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using Mrbr.Encryption.Data.Identity.Migration;
using Mrbr.Encryption.Data.Identity.Migration.Sqlite;

namespace Mrbr.Encryption.Data.Identity.Tests;

public sealed class SqliteIdentityTokenMigrationTests
{
    [Fact]
    public async Task PlaintextRemoval_RequiresApprovalAndReconcilesCheckpointFailure()
    {
        string databasePath = Path.Combine(Path.GetTempPath(), $"mrbr-migration-{Guid.NewGuid():N}.db");
        string connectionString = $"Data Source={databasePath};Foreign Keys=True;Pooling=False";
        try
        {
            await CreateLegacyDatabaseAsync(connectionString);
            Guid migrationId = Guid.CreateVersion7();
            RecordingCheckpointStore checkpoints = new();
            SqliteIdentityTokenMigrationSchemaExecutor schema = new(connectionString, migrationId);
            IdentityTokenMigrationCheckpoint checkpoint = AssertSuccess(await schema.CreateShadowSchemaAsync(
                MoveToPreflight(migrationId, 3),
                checkpoints));
            checkpoint = AssertSuccess(IdentityTokenMigrationStateMachine.Advance(
                checkpoint,
                IdentityTokenMigrationStage.BackfillInProgress,
                0,
                0,
                0));
            SqliteIdentityTokenMigrationSource source = new(connectionString);
            SqliteIdentityTokenMigrationBatchProcessor processor = new(
                connectionString,
                migrationId,
                new TestProtectionAdapter());
            checkpoint = AssertSuccess(await IdentityTokenMigrationCoordinator.BackfillAsync(
                checkpoint,
                source,
                processor,
                checkpoints,
                new IdentityTokenMigrationOptions { BatchSize = 2 }));
            checkpoint = AssertSuccess(await IdentityTokenMigrationCoordinator.VerifyAsync(
                checkpoint,
                source,
                processor,
                checkpoints,
                new IdentityTokenMigrationOptions { BatchSize = 2 }));
            checkpoint = AssertSuccess(await schema.CutoverAsync(checkpoint, checkpoints));
            checkpoint = AssertSuccess(IdentityTokenMigrationStateMachine.Advance(
                checkpoint,
                IdentityTokenMigrationStage.RuntimeVerified,
                checkpoint.SourceRowsScanned,
                checkpoint.TargetRowsReady,
                checkpoint.TargetRowsVerified));
            IdentityTokenMigrationPlaintextRemovalApproval approval = new(
                migrationId,
                backupRetentionAddressed: true,
                replicasAndExportsAddressed: true,
                irreversibleRemovalApproved: true);

            IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint> beforeWrites =
                await schema.RemoveRetainedPlaintextAsync(checkpoint, approval, checkpoints);
            Assert.False(beforeWrites.IsSuccess);
            Assert.Equal(IdentityTokenMigrationFailureCode.InvalidStageTransition, beforeWrites.FailureCode);

            checkpoint = AssertSuccess(await IdentityTokenMigrationCoordinator.AcceptProtectedWritesAsync(
                checkpoint,
                checkpoints));
            IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint> wrongMigration =
                await schema.RemoveRetainedPlaintextAsync(
                    checkpoint,
                    new IdentityTokenMigrationPlaintextRemovalApproval(
                        Guid.CreateVersion7(),
                        backupRetentionAddressed: true,
                        replicasAndExportsAddressed: true,
                        irreversibleRemovalApproved: true),
                    checkpoints);
            Assert.False(wrongMigration.IsSuccess);
            Assert.Equal(IdentityTokenMigrationFailureCode.OperatorApprovalRequired, wrongMigration.FailureCode);

            SqliteIdentityTokenMigrationNames names = new(migrationId);
            await Assert.ThrowsAsync<IOException>(async () =>
                await schema.RemoveRetainedPlaintextAsync(
                    checkpoint,
                    approval,
                    new ThrowingCheckpointStore()));
            Assert.Equal(0, await CountObjectsAsync(connectionString, names.LegacyTable));

            IdentityTokenMigrationCheckpoint removed = AssertSuccess(
                await schema.RemoveRetainedPlaintextAsync(checkpoint, approval, checkpoints));
            Assert.Equal(IdentityTokenMigrationStage.PlaintextRemoved, removed.Stage);
            Assert.Equal(3, await CountAsync(connectionString, names.ApplicationTable));
        }
        finally
        {
            File.Delete(databasePath);
        }
    }

    [Fact]
    public async Task Cancellation_RollsBackActiveBackfillBatchAndResumesFromDurableProgress()
    {
        string databasePath = Path.Combine(Path.GetTempPath(), $"mrbr-migration-{Guid.NewGuid():N}.db");
        string connectionString = $"Data Source={databasePath};Foreign Keys=True;Pooling=False";
        try
        {
            await CreateLegacyDatabaseAsync(connectionString);
            Guid migrationId = Guid.CreateVersion7();
            RecordingCheckpointStore setupCheckpoints = new();
            SqliteIdentityTokenMigrationSchemaExecutor schema = new(connectionString, migrationId);
            IdentityTokenMigrationCheckpoint checkpoint = AssertSuccess(await schema.CreateShadowSchemaAsync(
                MoveToPreflight(migrationId, 3),
                setupCheckpoints));
            checkpoint = AssertSuccess(IdentityTokenMigrationStateMachine.Advance(
                checkpoint,
                IdentityTokenMigrationStage.BackfillInProgress,
                0,
                0,
                0));
            SqliteIdentityTokenMigrationSource source = new(connectionString);
            SqliteIdentityTokenMigrationNames names = new(migrationId);
            RecordingCheckpointStore backfillCheckpoints = new();
            using CancellationTokenSource backfillCancellation = new();
            SqliteIdentityTokenMigrationBatchProcessor cancellingBackfill = new(
                connectionString,
                migrationId,
                new CancellingProtectionAdapter(backfillCancellation, cancelOnHashCall: 2));

            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
                await IdentityTokenMigrationCoordinator.BackfillAsync(
                    checkpoint,
                    source,
                    cancellingBackfill,
                    backfillCheckpoints,
                    new IdentityTokenMigrationOptions { BatchSize = 3 },
                    backfillCancellation.Token));

            Assert.Equal(0, await CountAsync(connectionString, names.ShadowTable));
            Assert.Empty(backfillCheckpoints.Saved);

            IdentityTokenMigrationCheckpoint backfillComplete = AssertSuccess(
                await IdentityTokenMigrationCoordinator.BackfillAsync(
                    checkpoint,
                    source,
                    new SqliteIdentityTokenMigrationBatchProcessor(
                        connectionString,
                        migrationId,
                        new TestProtectionAdapter()),
                    backfillCheckpoints,
                    new IdentityTokenMigrationOptions { BatchSize = 3 }));
            Assert.Equal(3, await CountAsync(connectionString, names.ShadowTable));

            RecordingCheckpointStore verificationCheckpoints = new();
            using CancellationTokenSource verificationCancellation = new();
            SqliteIdentityTokenMigrationBatchProcessor cancellingVerification = new(
                connectionString,
                migrationId,
                new CancellingProtectionAdapter(verificationCancellation, cancelOnHashCall: 2));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
                await IdentityTokenMigrationCoordinator.VerifyAsync(
                    backfillComplete,
                    source,
                    cancellingVerification,
                    verificationCheckpoints,
                    new IdentityTokenMigrationOptions { BatchSize = 3 },
                    verificationCancellation.Token));

            IdentityTokenMigrationCheckpoint durableVerification = Assert.Single(verificationCheckpoints.Saved);
            Assert.Equal(IdentityTokenMigrationStage.VerificationInProgress, durableVerification.Stage);
            Assert.Equal(0, durableVerification.TargetRowsVerified);
            Assert.Equal(3, await CountAsync(connectionString, names.ShadowTable));

            IdentityTokenMigrationCheckpoint verified = AssertSuccess(
                await IdentityTokenMigrationCoordinator.VerifyAsync(
                    durableVerification,
                    source,
                    new SqliteIdentityTokenMigrationBatchProcessor(
                        connectionString,
                        migrationId,
                        new TestProtectionAdapter()),
                    verificationCheckpoints,
                    new IdentityTokenMigrationOptions { BatchSize = 3 }));
            Assert.Equal(IdentityTokenMigrationStage.Verified, verified.Stage);
            Assert.Equal(3, verified.TargetRowsVerified);
        }
        finally
        {
            File.Delete(databasePath);
        }
    }

    [Fact]
    public async Task Verification_CorruptionReturnsStableFailureWithoutFalseProgress()
    {
        string databasePath = Path.Combine(Path.GetTempPath(), $"mrbr-migration-{Guid.NewGuid():N}.db");
        string connectionString = $"Data Source={databasePath};Foreign Keys=True;Pooling=False";
        try
        {
            await CreateLegacyDatabaseAsync(connectionString);
            Guid migrationId = Guid.CreateVersion7();
            RecordingCheckpointStore setupCheckpoints = new();
            SqliteIdentityTokenMigrationSchemaExecutor schema = new(connectionString, migrationId);
            IdentityTokenMigrationCheckpoint checkpoint = AssertSuccess(await schema.CreateShadowSchemaAsync(
                MoveToPreflight(migrationId, 3),
                setupCheckpoints));
            checkpoint = AssertSuccess(IdentityTokenMigrationStateMachine.Advance(
                checkpoint,
                IdentityTokenMigrationStage.BackfillInProgress,
                0,
                0,
                0));
            SqliteIdentityTokenMigrationSource source = new(connectionString);
            SqliteIdentityTokenMigrationBatchProcessor processor = new(
                connectionString,
                migrationId,
                new TestProtectionAdapter());
            IdentityTokenMigrationCheckpoint backfillComplete = AssertSuccess(
                await IdentityTokenMigrationCoordinator.BackfillAsync(
                    checkpoint,
                    source,
                    processor,
                    setupCheckpoints,
                    new IdentityTokenMigrationOptions { BatchSize = 3 }));
            SqliteIdentityTokenMigrationNames names = new(migrationId);

            await ExecuteAsync(
                connectionString,
                $"UPDATE \"{names.ShadowTable}\" SET \"LoginProvider\" = 'enc:not-base64' " +
                "WHERE \"UserId\" = 'user-a' AND \"Name\" = 'enc:bmFtZS1h'");
            RecordingCheckpointStore malformedCheckpoints = new();
            IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint> malformed =
                await IdentityTokenMigrationCoordinator.VerifyAsync(
                    backfillComplete,
                    source,
                    processor,
                    malformedCheckpoints,
                    new IdentityTokenMigrationOptions { BatchSize = 3 });

            Assert.False(malformed.IsSuccess);
            Assert.Equal(IdentityTokenMigrationFailureCode.InvalidPayload, malformed.FailureCode);
            IdentityTokenMigrationCheckpoint malformedDurable = Assert.Single(malformedCheckpoints.Saved);
            Assert.Equal(IdentityTokenMigrationStage.VerificationInProgress, malformedDurable.Stage);
            Assert.Equal(0, malformedDurable.TargetRowsVerified);

            await ExecuteAsync(
                connectionString,
                $"UPDATE \"{names.ShadowTable}\" SET \"LoginProvider\" = 'enc:b3RoZXItcHJvdmlkZXI=' " +
                "WHERE \"UserId\" = 'user-a' AND \"Name\" = 'enc:bmFtZS1h'");
            RecordingCheckpointStore mismatchCheckpoints = new();
            IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint> mismatch =
                await IdentityTokenMigrationCoordinator.VerifyAsync(
                    backfillComplete,
                    source,
                    processor,
                    mismatchCheckpoints,
                    new IdentityTokenMigrationOptions { BatchSize = 3 });

            Assert.False(mismatch.IsSuccess);
            Assert.Equal(IdentityTokenMigrationFailureCode.HashMismatch, mismatch.FailureCode);
            IdentityTokenMigrationCheckpoint mismatchDurable = Assert.Single(mismatchCheckpoints.Saved);
            Assert.Equal(0, mismatchDurable.TargetRowsVerified);
        }
        finally
        {
            File.Delete(databasePath);
        }
    }

    [Fact]
    public async Task SchemaOperations_ReconcileCommittedDdlAfterCheckpointPersistenceFailure()
    {
        string databasePath = Path.Combine(Path.GetTempPath(), $"mrbr-migration-{Guid.NewGuid():N}.db");
        string connectionString = $"Data Source={databasePath};Foreign Keys=True;Pooling=False";
        try
        {
            await CreateLegacyDatabaseAsync(connectionString);
            Guid migrationId = Guid.CreateVersion7();
            SqliteIdentityTokenMigrationNames names = new(migrationId);
            SqliteIdentityTokenMigrationSchemaExecutor schema = new(connectionString, migrationId);
            RecordingCheckpointStore checkpoints = new();
            IdentityTokenMigrationCheckpoint preflight = MoveToPreflight(migrationId, expectedRows: 3);

            await Assert.ThrowsAsync<IOException>(async () =>
                await schema.CreateShadowSchemaAsync(preflight, new ThrowingCheckpointStore()));
            Assert.Equal(1, await CountObjectsAsync(connectionString, names.ShadowTable));

            IdentityTokenMigrationCheckpoint checkpoint = AssertSuccess(
                await schema.CreateShadowSchemaAsync(preflight, checkpoints));
            Assert.Equal(IdentityTokenMigrationStage.ShadowSchemaCreated, checkpoint.Stage);
            checkpoint = AssertSuccess(IdentityTokenMigrationStateMachine.Advance(
                checkpoint,
                IdentityTokenMigrationStage.BackfillInProgress,
                0,
                0,
                0));
            SqliteIdentityTokenMigrationSource source = new(connectionString);
            SqliteIdentityTokenMigrationBatchProcessor processor = new(
                connectionString,
                migrationId,
                new TestProtectionAdapter());
            checkpoint = AssertSuccess(await IdentityTokenMigrationCoordinator.BackfillAsync(
                checkpoint,
                source,
                processor,
                checkpoints,
                new IdentityTokenMigrationOptions()));
            IdentityTokenMigrationCheckpoint verified = AssertSuccess(
                await IdentityTokenMigrationCoordinator.VerifyAsync(
                    checkpoint,
                    source,
                    processor,
                    checkpoints,
                    new IdentityTokenMigrationOptions()));

            await Assert.ThrowsAsync<IOException>(async () =>
                await schema.CutoverAsync(verified, new ThrowingCheckpointStore()));
            Assert.Equal(0, await CountObjectsAsync(connectionString, names.ShadowTable));
            Assert.Equal(1, await CountObjectsAsync(connectionString, names.LegacyTable));
            Assert.Equal(3, await CountAsync(connectionString, names.ApplicationTable));
            Assert.Equal(3, await CountAsync(connectionString, names.LegacyTable));

            IdentityTokenMigrationCheckpoint cutover = AssertSuccess(
                await schema.CutoverAsync(verified, checkpoints));
            Assert.Equal(IdentityTokenMigrationStage.CutoverComplete, cutover.Stage);

            await Assert.ThrowsAsync<IOException>(async () =>
                await schema.RollbackCutoverAsync(cutover, new ThrowingCheckpointStore()));
            Assert.Equal(1, await CountObjectsAsync(connectionString, names.ShadowTable));
            Assert.Equal(0, await CountObjectsAsync(connectionString, names.LegacyTable));
            Assert.Equal(3, await CountAsync(connectionString, names.ApplicationTable));
            Assert.Equal(3, await CountAsync(connectionString, names.ShadowTable));

            IdentityTokenMigrationCheckpoint rolledBack = AssertSuccess(
                await schema.RollbackCutoverAsync(cutover, checkpoints));
            Assert.Equal(IdentityTokenMigrationStage.RolledBack, rolledBack.Stage);
            Assert.Equal(1, await CountObjectsAsync(connectionString, names.ApplicationTable));
        }
        finally
        {
            File.Delete(databasePath);
        }
    }

    [Fact]
    public async Task FileDatabase_BackfillsVerifiesCutsOverAndRollsBackBeforeWrites()
    {
        string databasePath = Path.Combine(Path.GetTempPath(), $"mrbr-migration-{Guid.NewGuid():N}.db");
        string connectionString = $"Data Source={databasePath};Foreign Keys=True;Pooling=False";
        try
        {
            await CreateLegacyDatabaseAsync(connectionString);
            Guid migrationId = Guid.CreateVersion7();
            RecordingCheckpointStore checkpoints = new();
            IdentityTokenMigrationCheckpoint checkpoint = MoveToPreflight(migrationId, expectedRows: 3);
            SqliteIdentityTokenMigrationSchemaExecutor schema = new(connectionString, migrationId);

            checkpoint = AssertSuccess(await schema.CreateShadowSchemaAsync(checkpoint, checkpoints));
            checkpoint = AssertSuccess(IdentityTokenMigrationStateMachine.Advance(
                checkpoint,
                IdentityTokenMigrationStage.BackfillInProgress,
                0,
                0,
                0));

            SqliteIdentityTokenMigrationSource source = new(connectionString);
            TestProtectionAdapter protection = new();
            SqliteIdentityTokenMigrationBatchProcessor processor = new(
                connectionString,
                migrationId,
                protection);
            checkpoint = AssertSuccess(await IdentityTokenMigrationCoordinator.BackfillAsync(
                checkpoint,
                source,
                processor,
                checkpoints,
                new IdentityTokenMigrationOptions { BatchSize = 2 }));

            SqliteIdentityTokenMigrationNames names = new(migrationId);
            string rawProtected = await ReadScalarStringAsync(
                connectionString,
                $"SELECT \"LoginProvider\" || '|' || \"Name\" || '|' || COALESCE(\"Value\", '') FROM \"{names.ShadowTable}\" LIMIT 1");
            Assert.StartsWith("enc:", rawProtected, StringComparison.Ordinal);
            Assert.DoesNotContain("provider-a", rawProtected, StringComparison.Ordinal);
            Assert.DoesNotContain("token-a", rawProtected, StringComparison.Ordinal);

            checkpoint = AssertSuccess(await IdentityTokenMigrationCoordinator.VerifyAsync(
                checkpoint,
                source,
                processor,
                checkpoints,
                new IdentityTokenMigrationOptions { BatchSize = 2 }));
            checkpoint = AssertSuccess(await schema.CutoverAsync(checkpoint, checkpoints));

            Assert.Equal(IdentityTokenMigrationStage.CutoverComplete, checkpoint.Stage);
            Assert.Equal(3, await CountAsync(connectionString, names.ApplicationTable));
            Assert.Equal(3, await CountAsync(connectionString, names.LegacyTable));
            Assert.StartsWith(
                "enc:",
                await ReadScalarStringAsync(connectionString, "SELECT \"LoginProvider\" FROM \"AspNetUserTokens\" LIMIT 1"),
                StringComparison.Ordinal);
            Assert.False((await ReadScalarStringAsync(
                connectionString,
                $"SELECT \"LoginProvider\" FROM \"{names.LegacyTable}\" LIMIT 1"))
                .StartsWith("enc:", StringComparison.Ordinal));

            checkpoint = AssertSuccess(await schema.RollbackCutoverAsync(checkpoint, checkpoints));
            Assert.Equal(IdentityTokenMigrationStage.RolledBack, checkpoint.Stage);
            Assert.False((await ReadScalarStringAsync(
                connectionString,
                "SELECT \"LoginProvider\" FROM \"AspNetUserTokens\" LIMIT 1"))
                .StartsWith("enc:", StringComparison.Ordinal));
        }
        finally
        {
            File.Delete(databasePath);
        }
    }

    [Fact]
    public async Task Processor_RestartIdempotentlyVerifiesExistingRows()
    {
        string databasePath = Path.Combine(Path.GetTempPath(), $"mrbr-migration-{Guid.NewGuid():N}.db");
        string connectionString = $"Data Source={databasePath};Foreign Keys=True;Pooling=False";
        try
        {
            await CreateLegacyDatabaseAsync(connectionString);
            Guid migrationId = Guid.CreateVersion7();
            RecordingCheckpointStore checkpoints = new();
            SqliteIdentityTokenMigrationSchemaExecutor schema = new(connectionString, migrationId);
            await schema.CreateShadowSchemaAsync(MoveToPreflight(migrationId, 3), checkpoints);
            SqliteIdentityTokenMigrationSource source = new(connectionString);
            IReadOnlyList<LegacyIdentityTokenMigrationRow> rows = await source.ReadBatchAsync(0, 2, default);
            SqliteIdentityTokenMigrationBatchProcessor processor = new(
                connectionString,
                migrationId,
                new TestProtectionAdapter());

            Assert.Equal(2, AssertSuccess(await processor.WriteOrVerifyBatchAsync(rows, default)));
            Assert.Equal(2, AssertSuccess(await processor.WriteOrVerifyBatchAsync(rows, default)));

            SqliteIdentityTokenMigrationNames names = new(migrationId);
            Assert.Equal(2, await CountAsync(connectionString, names.ShadowTable));
        }
        finally
        {
            File.Delete(databasePath);
        }
    }

    [Fact]
    public async Task Rollback_IsRefusedAfterProtectedWritesAreAccepted()
    {
        string databasePath = Path.Combine(Path.GetTempPath(), $"mrbr-migration-{Guid.NewGuid():N}.db");
        string connectionString = $"Data Source={databasePath};Foreign Keys=True;Pooling=False";
        try
        {
            await CreateLegacyDatabaseAsync(connectionString, includeTokens: false);
            Guid migrationId = Guid.CreateVersion7();
            RecordingCheckpointStore checkpoints = new();
            SqliteIdentityTokenMigrationSchemaExecutor schema = new(connectionString, migrationId);
            IdentityTokenMigrationCheckpoint checkpoint = MoveToPreflight(migrationId, 0);
            checkpoint = AssertSuccess(await schema.CreateShadowSchemaAsync(checkpoint, checkpoints));
            checkpoint = AssertSuccess(IdentityTokenMigrationStateMachine.Advance(
                checkpoint, IdentityTokenMigrationStage.BackfillInProgress, 0, 0, 0));
            checkpoint = AssertSuccess(await IdentityTokenMigrationCoordinator.BackfillAsync(
                checkpoint,
                new SqliteIdentityTokenMigrationSource(connectionString),
                new SqliteIdentityTokenMigrationBatchProcessor(connectionString, migrationId, new TestProtectionAdapter()),
                checkpoints,
                new IdentityTokenMigrationOptions()));
            checkpoint = AssertSuccess(await IdentityTokenMigrationCoordinator.VerifyAsync(
                checkpoint,
                new SqliteIdentityTokenMigrationSource(connectionString),
                new SqliteIdentityTokenMigrationBatchProcessor(connectionString, migrationId, new TestProtectionAdapter()),
                checkpoints,
                new IdentityTokenMigrationOptions()));
            checkpoint = AssertSuccess(await schema.CutoverAsync(checkpoint, checkpoints));
            checkpoint = AssertSuccess(IdentityTokenMigrationStateMachine.Advance(
                checkpoint,
                IdentityTokenMigrationStage.RuntimeVerified,
                checkpoint.SourceRowsScanned,
                checkpoint.TargetRowsReady,
                checkpoint.TargetRowsVerified));
            checkpoint = AssertSuccess(IdentityTokenMigrationStateMachine.AcceptProtectedWrites(checkpoint));

            var rollback = await schema.RollbackCutoverAsync(checkpoint, checkpoints);

            Assert.False(rollback.IsSuccess);
            Assert.Equal(IdentityTokenMigrationFailureCode.RollbackUnsafe, rollback.FailureCode);
        }
        finally
        {
            File.Delete(databasePath);
        }
    }

    [Fact]
    public async Task ShadowCreation_RejectsUnexpectedLegacySchemaWithoutMutation()
    {
        string databasePath = Path.Combine(Path.GetTempPath(), $"mrbr-migration-{Guid.NewGuid():N}.db");
        string connectionString = $"Data Source={databasePath};Foreign Keys=True;Pooling=False";
        try
        {
            await using (SqliteConnection connection = new(connectionString))
            {
                await connection.OpenAsync();
                await using SqliteCommand command = connection.CreateCommand();
                command.CommandText =
                    "CREATE TABLE \"AspNetUsers\" (\"Id\" TEXT NOT NULL PRIMARY KEY);" +
                    "CREATE TABLE \"AspNetUserTokens\" (\"UserId\" TEXT NOT NULL PRIMARY KEY, \"Value\" TEXT NULL);";
                await command.ExecuteNonQueryAsync();
            }

            Guid migrationId = Guid.CreateVersion7();
            SqliteIdentityTokenMigrationSchemaExecutor schema = new(connectionString, migrationId);
            var result = await schema.CreateShadowSchemaAsync(
                MoveToPreflight(migrationId, 0),
                new RecordingCheckpointStore());

            Assert.False(result.IsSuccess);
            Assert.Equal(IdentityTokenMigrationFailureCode.InvalidSourceRow, result.FailureCode);
            Assert.Equal(0, await CountObjectsAsync(
                connectionString,
                new SqliteIdentityTokenMigrationNames(migrationId).ShadowTable));
        }
        finally
        {
            File.Delete(databasePath);
        }
    }

    [Fact]
    public async Task Verification_ReturnsKnownFailureForMalformedTargetIdentifier()
    {
        string databasePath = Path.Combine(Path.GetTempPath(), $"mrbr-migration-{Guid.NewGuid():N}.db");
        string connectionString = $"Data Source={databasePath};Foreign Keys=True;Pooling=False";
        try
        {
            await CreateLegacyDatabaseAsync(connectionString);
            Guid migrationId = Guid.CreateVersion7();
            RecordingCheckpointStore checkpoints = new();
            SqliteIdentityTokenMigrationSchemaExecutor schema = new(connectionString, migrationId);
            await schema.CreateShadowSchemaAsync(MoveToPreflight(migrationId, 3), checkpoints);
            SqliteIdentityTokenMigrationSource source = new(connectionString);
            IReadOnlyList<LegacyIdentityTokenMigrationRow> rows = await source.ReadBatchAsync(0, 1, default);
            SqliteIdentityTokenMigrationBatchProcessor processor = new(
                connectionString,
                migrationId,
                new TestProtectionAdapter());
            Assert.Equal(1, AssertSuccess(await processor.WriteOrVerifyBatchAsync(rows, default)));

            SqliteIdentityTokenMigrationNames names = new(migrationId);
            await ExecuteAsync(connectionString, $"UPDATE \"{names.ShadowTable}\" SET \"TokenId\" = 'malformed'");
            var result = await processor.VerifyBatchAsync(rows, default);

            Assert.False(result.IsSuccess);
            Assert.Equal(IdentityTokenMigrationFailureCode.InvalidPayload, result.FailureCode);
        }
        finally
        {
            File.Delete(databasePath);
        }
    }

    private static async Task CreateLegacyDatabaseAsync(string connectionString, bool includeTokens = true)
    {
        await using SqliteConnection connection = new(connectionString);
        await connection.OpenAsync();
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            "CREATE TABLE \"AspNetUsers\" (\"Id\" TEXT NOT NULL PRIMARY KEY);" +
            "CREATE TABLE \"AspNetUserTokens\" (" +
            "\"UserId\" TEXT NOT NULL, \"LoginProvider\" TEXT NOT NULL, \"Name\" TEXT NOT NULL, \"Value\" TEXT NULL, " +
            "CONSTRAINT \"PK_AspNetUserTokens\" PRIMARY KEY (\"UserId\", \"LoginProvider\", \"Name\"), " +
            "CONSTRAINT \"FK_AspNetUserTokens_AspNetUsers_UserId\" FOREIGN KEY (\"UserId\") REFERENCES \"AspNetUsers\" (\"Id\") ON DELETE CASCADE);" +
            "INSERT INTO \"AspNetUsers\" (\"Id\") VALUES ('user-a'), ('user-b');";
        if (includeTokens)
        {
            command.CommandText +=
                "INSERT INTO \"AspNetUserTokens\" (\"UserId\", \"LoginProvider\", \"Name\", \"Value\") VALUES " +
                "('user-a', 'provider-a', 'name-a', 'token-a'), " +
                "('user-a', 'provider-b', 'name-b', NULL), " +
                "('user-b', 'provider-a', 'name-empty', '');";
        }

        await command.ExecuteNonQueryAsync();
    }

    private static IdentityTokenMigrationCheckpoint MoveToPreflight(Guid migrationId, long expectedRows)
    {
        IdentityTokenMigrationCheckpoint checkpoint = AssertSuccess(
            IdentityTokenMigrationStateMachine.Create(migrationId, expectedRows));
        return AssertSuccess(IdentityTokenMigrationStateMachine.Advance(
            checkpoint, IdentityTokenMigrationStage.PreflightPassed, 0, 0, 0));
    }

    private static async Task<long> CountAsync(string connectionString, string table)
    {
        await using SqliteConnection connection = new(connectionString);
        await connection.OpenAsync();
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = $"SELECT COUNT(*) FROM \"{table}\"";
        return Convert.ToInt64(await command.ExecuteScalarAsync(), System.Globalization.CultureInfo.InvariantCulture);
    }

    private static async Task<string> ReadScalarStringAsync(string connectionString, string sql)
    {
        await using SqliteConnection connection = new(connectionString);
        await connection.OpenAsync();
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = sql;
        return (string)(await command.ExecuteScalarAsync())!;
    }

    private static async Task<long> CountObjectsAsync(string connectionString, string objectName)
    {
        await using SqliteConnection connection = new(connectionString);
        await connection.OpenAsync();
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE name = $name";
        command.Parameters.AddWithValue("$name", objectName);
        return Convert.ToInt64(await command.ExecuteScalarAsync(), System.Globalization.CultureInfo.InvariantCulture);
    }

    private static async Task ExecuteAsync(string connectionString, string sql)
    {
        await using SqliteConnection connection = new(connectionString);
        await connection.OpenAsync();
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync();
    }

    private static T AssertSuccess<T>(IdentityTokenMigrationResult<T> result)
    {
        Assert.True(result.IsSuccess, $"Expected success, received {result.FailureCode}.");
        return result.Value;
    }

    private sealed class RecordingCheckpointStore : IIdentityTokenMigrationCheckpointStore
    {
        public List<IdentityTokenMigrationCheckpoint> Saved { get; } = [];

        public ValueTask SaveAsync(IdentityTokenMigrationCheckpoint checkpoint, CancellationToken cancellationToken)
        {
            Saved.Add(checkpoint);
            return ValueTask.CompletedTask;
        }
    }

    private sealed class ThrowingCheckpointStore : IIdentityTokenMigrationCheckpointStore
    {
        public ValueTask SaveAsync(
            IdentityTokenMigrationCheckpoint checkpoint,
            CancellationToken cancellationToken) =>
            ValueTask.FromException(new IOException("Synthetic checkpoint persistence failure."));
    }

    private sealed class CancellingProtectionAdapter(
        CancellationTokenSource cancellation,
        int cancelOnHashCall) : IIdentityTokenMigrationProtectionAdapter
    {
        private readonly TestProtectionAdapter _inner = new();
        private int _hashCalls;

        public IdentityTokenMigrationResult<string> ComputeRoutingHash(LegacyIdentityTokenMigrationRow sourceRow)
        {
            IdentityTokenMigrationResult<string> result = _inner.ComputeRoutingHash(sourceRow);
            if (Interlocked.Increment(ref _hashCalls) == cancelOnHashCall)
            {
                cancellation.Cancel();
            }

            return result;
        }

        public IdentityTokenMigrationResult<ProtectedIdentityTokenMigrationRow> Protect(
            LegacyIdentityTokenMigrationRow sourceRow,
            Guid tokenId,
            string routingHash) =>
            _inner.Protect(sourceRow, tokenId, routingHash);

        public IdentityTokenMigrationResult<bool> Verify(
            LegacyIdentityTokenMigrationRow sourceRow,
            ProtectedIdentityTokenMigrationRow targetRow) =>
            _inner.Verify(sourceRow, targetRow);
    }

    private sealed class TestProtectionAdapter : IIdentityTokenMigrationProtectionAdapter
    {
        public IdentityTokenMigrationResult<string> ComputeRoutingHash(LegacyIdentityTokenMigrationRow sourceRow) =>
            IdentityTokenMigrationResult<string>.Success(Hash(sourceRow));

        public IdentityTokenMigrationResult<ProtectedIdentityTokenMigrationRow> Protect(
            LegacyIdentityTokenMigrationRow sourceRow,
            Guid tokenId,
            string routingHash) =>
            IdentityTokenMigrationResult<ProtectedIdentityTokenMigrationRow>.Success(
                new ProtectedIdentityTokenMigrationRow(
                    tokenId,
                    sourceRow.UserId,
                    Encrypt(sourceRow.LoginProvider),
                    Encrypt(sourceRow.Name),
                    sourceRow.Value is null ? null : Encrypt(sourceRow.Value),
                    routingHash));

        public IdentityTokenMigrationResult<bool> Verify(
            LegacyIdentityTokenMigrationRow sourceRow,
            ProtectedIdentityTokenMigrationRow targetRow)
        {
            try
            {
                bool matches = targetRow.TokenId.Version == 7 &&
                    string.Equals(targetRow.UserId, sourceRow.UserId, StringComparison.Ordinal) &&
                    string.Equals(Decrypt(targetRow.EncryptedLoginProvider), sourceRow.LoginProvider, StringComparison.Ordinal) &&
                    string.Equals(Decrypt(targetRow.EncryptedName), sourceRow.Name, StringComparison.Ordinal) &&
                    string.Equals(
                        targetRow.EncryptedValue is null ? null : Decrypt(targetRow.EncryptedValue),
                        sourceRow.Value,
                        StringComparison.Ordinal) &&
                    string.Equals(targetRow.RoutingHash, Hash(sourceRow), StringComparison.Ordinal);
                return matches
                    ? IdentityTokenMigrationResult<bool>.Success(true)
                    : IdentityTokenMigrationResult<bool>.Failure(IdentityTokenMigrationFailureCode.HashMismatch);
            }
            catch (FormatException)
            {
                return IdentityTokenMigrationResult<bool>.Failure(IdentityTokenMigrationFailureCode.InvalidPayload);
            }
        }

        private static string Encrypt(string value) =>
            "enc:" + Convert.ToBase64String(Encoding.UTF8.GetBytes(value));

        private static string Decrypt(string value) =>
            Encoding.UTF8.GetString(Convert.FromBase64String(value["enc:".Length..]));

        private static string Hash(LegacyIdentityTokenMigrationRow row)
        {
            string input = $"{row.UserId.Length}:{row.UserId}{row.LoginProvider.Length}:{row.LoginProvider}{row.Name.Length}:{row.Name}";
            return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(input)));
        }
    }
}
