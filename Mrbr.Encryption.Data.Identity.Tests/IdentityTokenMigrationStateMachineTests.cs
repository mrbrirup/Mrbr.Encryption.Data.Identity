using Mrbr.Encryption.Data.Identity.Migration;

namespace Mrbr.Encryption.Data.Identity.Tests;

public sealed class IdentityTokenMigrationStateMachineTests
{
    [Fact]
    public void Create_UsesVersion7IdentifierAndDoesNotContainPlaintextCursor()
    {
        IdentityTokenMigrationCheckpoint checkpoint = AssertSuccess(
            IdentityTokenMigrationStateMachine.Create(expectedSourceRows: 12));

        Assert.Equal(7, checkpoint.MigrationId.Version);
        Assert.Equal(IdentityTokenMigrationStage.Created, checkpoint.Stage);
        Assert.DoesNotContain(
            typeof(IdentityTokenMigrationCheckpoint).GetProperties(),
            property => property.Name.Contains("Provider", StringComparison.Ordinal) ||
                        property.Name.Contains("Name", StringComparison.Ordinal) ||
                        property.Name.Contains("Value", StringComparison.Ordinal));
    }

    [Fact]
    public void Create_RejectsNonVersion7Identifier()
    {
        var result = IdentityTokenMigrationStateMachine.Create(Guid.NewGuid(), 1);

        Assert.False(result.IsSuccess);
        Assert.Equal(IdentityTokenMigrationFailureCode.InvalidMigrationIdentifier, result.FailureCode);
    }

    [Fact]
    public void Advance_RejectsSkippedStage()
    {
        IdentityTokenMigrationCheckpoint checkpoint = AssertSuccess(
            IdentityTokenMigrationStateMachine.Create(1));

        var result = IdentityTokenMigrationStateMachine.Advance(
            checkpoint,
            IdentityTokenMigrationStage.ShadowSchemaCreated,
            0,
            0,
            0);

        Assert.False(result.IsSuccess);
        Assert.Equal(IdentityTokenMigrationFailureCode.InvalidStageTransition, result.FailureCode);
    }

    [Fact]
    public void Backfill_AllowsMonotonicCommittedBatchProgress()
    {
        IdentityTokenMigrationCheckpoint checkpoint = MoveToBackfill(expectedRows: 10);

        checkpoint = AssertSuccess(IdentityTokenMigrationStateMachine.Advance(
            checkpoint,
            IdentityTokenMigrationStage.BackfillInProgress,
            sourceRowsScanned: 4,
            targetRowsReady: 4,
            targetRowsVerified: 0));
        checkpoint = AssertSuccess(IdentityTokenMigrationStateMachine.Advance(
            checkpoint,
            IdentityTokenMigrationStage.BackfillInProgress,
            sourceRowsScanned: 10,
            targetRowsReady: 10,
            targetRowsVerified: 0));

        Assert.Equal(10, checkpoint.SourceRowsScanned);
        Assert.Equal(10, checkpoint.TargetRowsReady);
    }

    [Fact]
    public void Backfill_RejectsDecreasingOrImpossibleCounters()
    {
        IdentityTokenMigrationCheckpoint checkpoint = MoveToBackfill(expectedRows: 10);
        checkpoint = AssertSuccess(IdentityTokenMigrationStateMachine.Advance(
            checkpoint,
            IdentityTokenMigrationStage.BackfillInProgress,
            5,
            5,
            0));

        var result = IdentityTokenMigrationStateMachine.Advance(
            checkpoint,
            IdentityTokenMigrationStage.BackfillInProgress,
            4,
            6,
            0);

        Assert.False(result.IsSuccess);
        Assert.Equal(IdentityTokenMigrationFailureCode.InvalidRowCounts, result.FailureCode);
    }

    [Fact]
    public void BackfillComplete_RequiresEverySourceRowReady()
    {
        IdentityTokenMigrationCheckpoint checkpoint = MoveToBackfill(expectedRows: 10);

        var result = IdentityTokenMigrationStateMachine.Advance(
            checkpoint,
            IdentityTokenMigrationStage.BackfillComplete,
            9,
            9,
            0);

        Assert.False(result.IsSuccess);
        Assert.Equal(IdentityTokenMigrationFailureCode.SourceChanged, result.FailureCode);
    }

    [Fact]
    public void Verified_RequiresEveryTargetRowVerified()
    {
        IdentityTokenMigrationCheckpoint checkpoint = MoveToBackfill(expectedRows: 2);
        checkpoint = AssertSuccess(IdentityTokenMigrationStateMachine.Advance(
            checkpoint,
            IdentityTokenMigrationStage.BackfillComplete,
            2,
            2,
            0));
        checkpoint = AssertSuccess(IdentityTokenMigrationStateMachine.Advance(
            checkpoint,
            IdentityTokenMigrationStage.VerificationInProgress,
            2,
            2,
            0));

        var result = IdentityTokenMigrationStateMachine.Advance(
            checkpoint,
            IdentityTokenMigrationStage.Verified,
            2,
            2,
            1);

        Assert.False(result.IsSuccess);
        Assert.Equal(IdentityTokenMigrationFailureCode.VerificationFailed, result.FailureCode);
    }

    [Fact]
    public void ProtectedWritesCloseMetadataOnlyRollbackBoundary()
    {
        IdentityTokenMigrationCheckpoint checkpoint = MoveToCutover(expectedRows: 1);
        Assert.True(checkpoint.CanRollbackByTableSwap);
        Assert.True(IdentityTokenMigrationStateMachine.ValidateTableSwapRollback(checkpoint).IsSuccess);

        var premature = IdentityTokenMigrationStateMachine.AcceptProtectedWrites(checkpoint);
        Assert.False(premature.IsSuccess);
        Assert.Equal(IdentityTokenMigrationFailureCode.InvalidStageTransition, premature.FailureCode);

        checkpoint = AssertSuccess(IdentityTokenMigrationStateMachine.Advance(
            checkpoint,
            IdentityTokenMigrationStage.RuntimeVerified,
            1,
            1,
            1));
        Assert.True(checkpoint.CanRollbackByTableSwap);

        checkpoint = AssertSuccess(IdentityTokenMigrationStateMachine.AcceptProtectedWrites(checkpoint));
        var rollback = IdentityTokenMigrationStateMachine.ValidateTableSwapRollback(checkpoint);

        Assert.False(checkpoint.CanRollbackByTableSwap);
        Assert.False(rollback.IsSuccess);
        Assert.Equal(IdentityTokenMigrationFailureCode.RollbackUnsafe, rollback.FailureCode);
    }

    [Fact]
    public void Restore_RejectsCheckpointThatSkipsFullVerification()
    {
        Guid migrationId = Guid.CreateVersion7();

        var result = IdentityTokenMigrationStateMachine.Restore(
            migrationId,
            IdentityTokenMigrationStage.Verified,
            expectedSourceRows: 4,
            sourceRowsScanned: 4,
            targetRowsReady: 4,
            targetRowsVerified: 3,
            protectedWritesAccepted: false);

        Assert.False(result.IsSuccess);
        Assert.Equal(IdentityTokenMigrationFailureCode.VerificationFailed, result.FailureCode);
    }

    [Fact]
    public void Restore_AcceptsValidBackfillCheckpointWithoutPlaintextCursor()
    {
        Guid migrationId = Guid.CreateVersion7();

        IdentityTokenMigrationCheckpoint checkpoint = AssertSuccess(
            IdentityTokenMigrationStateMachine.Restore(
                migrationId,
                IdentityTokenMigrationStage.BackfillInProgress,
                expectedSourceRows: 100,
                sourceRowsScanned: 40,
                targetRowsReady: 40,
                targetRowsVerified: 0,
                protectedWritesAccepted: false));

        Assert.Equal(migrationId, checkpoint.MigrationId);
        Assert.Equal(40, checkpoint.SourceRowsScanned);
    }

    [Fact]
    public void PlaintextRemoval_RequiresExplicitProtectedWriteBoundary()
    {
        IdentityTokenMigrationCheckpoint checkpoint = MoveToCutover(expectedRows: 1);
        checkpoint = AssertSuccess(IdentityTokenMigrationStateMachine.Advance(
            checkpoint,
            IdentityTokenMigrationStage.RuntimeVerified,
            1,
            1,
            1));

        var rejected = IdentityTokenMigrationStateMachine.Advance(
            checkpoint,
            IdentityTokenMigrationStage.PlaintextRemoved,
            1,
            1,
            1);
        Assert.False(rejected.IsSuccess);
        Assert.Equal(IdentityTokenMigrationFailureCode.InvalidStageTransition, rejected.FailureCode);

        checkpoint = AssertSuccess(IdentityTokenMigrationStateMachine.AcceptProtectedWrites(checkpoint));
        IdentityTokenMigrationCheckpoint removed = AssertSuccess(
            IdentityTokenMigrationStateMachine.Advance(
                checkpoint,
                IdentityTokenMigrationStage.PlaintextRemoved,
                1,
                1,
                1));
        Assert.Equal(IdentityTokenMigrationStage.PlaintextRemoved, removed.Stage);
    }

    [Fact]
    public void RollbackState_IsTerminalAndCannotBeReachedByNormalAdvance()
    {
        IdentityTokenMigrationCheckpoint checkpoint = MoveToCutover(expectedRows: 1);

        var normalAdvance = IdentityTokenMigrationStateMachine.Advance(
            checkpoint,
            IdentityTokenMigrationStage.RolledBack,
            1,
            1,
            1);
        Assert.False(normalAdvance.IsSuccess);

        IdentityTokenMigrationCheckpoint rolledBack = AssertSuccess(
            IdentityTokenMigrationStateMachine.RecordTableSwapRollback(checkpoint));
        Assert.Equal(IdentityTokenMigrationStage.RolledBack, rolledBack.Stage);
        Assert.False(IdentityTokenMigrationStateMachine.Advance(
            rolledBack,
            IdentityTokenMigrationStage.PlaintextRemoved,
            1,
            1,
            1).IsSuccess);
    }

    private static IdentityTokenMigrationCheckpoint MoveToBackfill(long expectedRows)
    {
        IdentityTokenMigrationCheckpoint checkpoint = AssertSuccess(
            IdentityTokenMigrationStateMachine.Create(expectedRows));
        checkpoint = AssertSuccess(IdentityTokenMigrationStateMachine.Advance(
            checkpoint, IdentityTokenMigrationStage.PreflightPassed, 0, 0, 0));
        checkpoint = AssertSuccess(IdentityTokenMigrationStateMachine.Advance(
            checkpoint, IdentityTokenMigrationStage.ShadowSchemaCreated, 0, 0, 0));
        return AssertSuccess(IdentityTokenMigrationStateMachine.Advance(
            checkpoint, IdentityTokenMigrationStage.BackfillInProgress, 0, 0, 0));
    }

    private static IdentityTokenMigrationCheckpoint MoveToCutover(long expectedRows)
    {
        IdentityTokenMigrationCheckpoint checkpoint = MoveToBackfill(expectedRows);
        checkpoint = AssertSuccess(IdentityTokenMigrationStateMachine.Advance(
            checkpoint, IdentityTokenMigrationStage.BackfillComplete, expectedRows, expectedRows, 0));
        checkpoint = AssertSuccess(IdentityTokenMigrationStateMachine.Advance(
            checkpoint, IdentityTokenMigrationStage.VerificationInProgress, expectedRows, expectedRows, 0));
        checkpoint = AssertSuccess(IdentityTokenMigrationStateMachine.Advance(
            checkpoint, IdentityTokenMigrationStage.Verified, expectedRows, expectedRows, expectedRows));
        return AssertSuccess(IdentityTokenMigrationStateMachine.Advance(
            checkpoint, IdentityTokenMigrationStage.CutoverComplete, expectedRows, expectedRows, expectedRows));
    }

    private static T AssertSuccess<T>(IdentityTokenMigrationResult<T> result)
    {
        Assert.True(result.IsSuccess, $"Expected success, received {result.FailureCode}.");
        return result.Value;
    }
}
