namespace Mrbr.Encryption.Data.Identity.Migration;

/// <summary>Enforces the durable ordering and rollback boundary of an offline token migration.</summary>
public static class IdentityTokenMigrationStateMachine
{
    /// <summary>Creates a migration checkpoint using an application-generated UUIDv7 identifier.</summary>
    public static IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint> Create(long expectedSourceRows) =>
        Create(Guid.CreateVersion7(), expectedSourceRows);

    /// <summary>Creates a migration checkpoint with an explicit UUIDv7 identifier.</summary>
    public static IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint> Create(
        Guid migrationId,
        long expectedSourceRows)
    {
        if (migrationId == Guid.Empty || migrationId.Version != 7)
        {
            return IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint>.Failure(
                IdentityTokenMigrationFailureCode.InvalidMigrationIdentifier);
        }

        if (expectedSourceRows < 0)
        {
            return IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint>.Failure(
                IdentityTokenMigrationFailureCode.InvalidRowCounts);
        }

        return Success(
            migrationId,
            IdentityTokenMigrationStage.Created,
            expectedSourceRows,
            0,
            0,
            0,
            protectedWritesAccepted: false);
    }

    /// <summary>Restores a durable checkpoint only when all stage and counter invariants still hold.</summary>
    public static IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint> Restore(
        Guid migrationId,
        IdentityTokenMigrationStage stage,
        long expectedSourceRows,
        long sourceRowsScanned,
        long targetRowsReady,
        long targetRowsVerified,
        bool protectedWritesAccepted)
    {
        if (migrationId == Guid.Empty || migrationId.Version != 7)
        {
            return Failure(IdentityTokenMigrationFailureCode.InvalidMigrationIdentifier);
        }

        IdentityTokenMigrationFailureCode validation = ValidateState(
            stage,
            expectedSourceRows,
            sourceRowsScanned,
            targetRowsReady,
            targetRowsVerified,
            protectedWritesAccepted);
        return validation == IdentityTokenMigrationFailureCode.None
            ? Success(
                migrationId,
                stage,
                expectedSourceRows,
                sourceRowsScanned,
                targetRowsReady,
                targetRowsVerified,
                protectedWritesAccepted)
            : Failure(validation);
    }

    /// <summary>Advances one durable stage or records monotonic progress within backfill.</summary>
    public static IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint> Advance(
        IdentityTokenMigrationCheckpoint checkpoint,
        IdentityTokenMigrationStage nextStage,
        long sourceRowsScanned,
        long targetRowsReady,
        long targetRowsVerified)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);

        if (!IsAllowedTransition(checkpoint.Stage, nextStage))
        {
            return Failure(IdentityTokenMigrationFailureCode.InvalidStageTransition);
        }

        if (!CountsAreMonotonicAndBounded(
                checkpoint,
                sourceRowsScanned,
                targetRowsReady,
                targetRowsVerified))
        {
            return Failure(IdentityTokenMigrationFailureCode.InvalidRowCounts);
        }

        IdentityTokenMigrationFailureCode validation = ValidateState(
            nextStage,
            checkpoint.ExpectedSourceRows,
            sourceRowsScanned,
            targetRowsReady,
            targetRowsVerified,
            checkpoint.ProtectedWritesAccepted);
        if (validation != IdentityTokenMigrationFailureCode.None)
        {
            return Failure(validation);
        }

        return Success(
            checkpoint.MigrationId,
            nextStage,
            checkpoint.ExpectedSourceRows,
            sourceRowsScanned,
            targetRowsReady,
            targetRowsVerified,
            checkpoint.ProtectedWritesAccepted);
    }

    /// <summary>Marks the point after which a metadata-only rollback would lose protected-table writes.</summary>
    public static IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint> AcceptProtectedWrites(
        IdentityTokenMigrationCheckpoint checkpoint)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);

        if (checkpoint.Stage != IdentityTokenMigrationStage.RuntimeVerified)
        {
            return Failure(IdentityTokenMigrationFailureCode.InvalidStageTransition);
        }

        return Success(
            checkpoint.MigrationId,
            checkpoint.Stage,
            checkpoint.ExpectedSourceRows,
            checkpoint.SourceRowsScanned,
            checkpoint.TargetRowsReady,
            checkpoint.TargetRowsVerified,
            protectedWritesAccepted: true);
    }

    /// <summary>Validates that a metadata-only rollback remains safe.</summary>
    public static IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint> ValidateTableSwapRollback(
        IdentityTokenMigrationCheckpoint checkpoint)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);
        return checkpoint.CanRollbackByTableSwap
            ? IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint>.Success(checkpoint)
            : Failure(IdentityTokenMigrationFailureCode.RollbackUnsafe);
    }

    /// <summary>Records a successful pre-write table-swap rollback as a terminal migration state.</summary>
    public static IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint> RecordTableSwapRollback(
        IdentityTokenMigrationCheckpoint checkpoint)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);
        if (!checkpoint.CanRollbackByTableSwap)
        {
            return Failure(IdentityTokenMigrationFailureCode.RollbackUnsafe);
        }

        return Success(
            checkpoint.MigrationId,
            IdentityTokenMigrationStage.RolledBack,
            checkpoint.ExpectedSourceRows,
            checkpoint.SourceRowsScanned,
            checkpoint.TargetRowsReady,
            checkpoint.TargetRowsVerified,
            protectedWritesAccepted: false);
    }

    private static bool IsAllowedTransition(
        IdentityTokenMigrationStage currentStage,
        IdentityTokenMigrationStage nextStage) =>
        nextStage != IdentityTokenMigrationStage.RolledBack &&
        (((currentStage == IdentityTokenMigrationStage.BackfillInProgress ||
          currentStage == IdentityTokenMigrationStage.VerificationInProgress) &&
         nextStage == currentStage) ||
         (int)nextStage == (int)currentStage + 1);

    private static bool CountsAreMonotonicAndBounded(
        IdentityTokenMigrationCheckpoint checkpoint,
        long sourceRowsScanned,
        long targetRowsReady,
        long targetRowsVerified) =>
        sourceRowsScanned >= checkpoint.SourceRowsScanned &&
        targetRowsReady >= checkpoint.TargetRowsReady &&
        targetRowsVerified >= checkpoint.TargetRowsVerified &&
        sourceRowsScanned <= checkpoint.ExpectedSourceRows &&
        targetRowsReady <= sourceRowsScanned &&
        targetRowsVerified <= targetRowsReady;

    private static IdentityTokenMigrationFailureCode ValidateState(
        IdentityTokenMigrationStage stage,
        long expectedSourceRows,
        long sourceRowsScanned,
        long targetRowsReady,
        long targetRowsVerified,
        bool protectedWritesAccepted)
    {
        if (!Enum.IsDefined(stage) ||
            expectedSourceRows < 0 ||
            sourceRowsScanned < 0 ||
            targetRowsReady < 0 ||
            targetRowsVerified < 0 ||
            sourceRowsScanned > expectedSourceRows ||
            targetRowsReady > sourceRowsScanned ||
            targetRowsVerified > targetRowsReady)
        {
            return IdentityTokenMigrationFailureCode.InvalidRowCounts;
        }

        if (stage < IdentityTokenMigrationStage.BackfillInProgress &&
            (sourceRowsScanned != 0 || targetRowsReady != 0 || targetRowsVerified != 0))
        {
            return IdentityTokenMigrationFailureCode.InvalidRowCounts;
        }

        if (stage < IdentityTokenMigrationStage.VerificationInProgress && targetRowsVerified != 0)
        {
            return IdentityTokenMigrationFailureCode.InvalidRowCounts;
        }

        if (stage >= IdentityTokenMigrationStage.BackfillComplete &&
            (sourceRowsScanned != expectedSourceRows || targetRowsReady != expectedSourceRows))
        {
            return IdentityTokenMigrationFailureCode.SourceChanged;
        }

        if (stage >= IdentityTokenMigrationStage.Verified && targetRowsVerified != expectedSourceRows)
        {
            return IdentityTokenMigrationFailureCode.VerificationFailed;
        }

        if ((protectedWritesAccepted && stage < IdentityTokenMigrationStage.RuntimeVerified) ||
            (stage == IdentityTokenMigrationStage.PlaintextRemoved && !protectedWritesAccepted))
        {
            return IdentityTokenMigrationFailureCode.InvalidStageTransition;
        }

        return IdentityTokenMigrationFailureCode.None;
    }

    private static IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint> Success(
        Guid migrationId,
        IdentityTokenMigrationStage stage,
        long expectedSourceRows,
        long sourceRowsScanned,
        long targetRowsReady,
        long targetRowsVerified,
        bool protectedWritesAccepted) =>
        IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint>.Success(
            new IdentityTokenMigrationCheckpoint(
                migrationId,
                stage,
                expectedSourceRows,
                sourceRowsScanned,
                targetRowsReady,
                targetRowsVerified,
                protectedWritesAccepted));

    private static IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint> Failure(
        IdentityTokenMigrationFailureCode code) =>
        IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint>.Failure(code);
}
