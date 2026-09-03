namespace Mrbr.Encryption.Data.Identity.Migration;

/// <summary>Coordinates resumable batches independently of a relational database provider.</summary>
public static class IdentityTokenMigrationCoordinator
{
    /// <summary>Backfills all remaining frozen source rows and records progress after each committed batch.</summary>
    public static async ValueTask<IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint>> BackfillAsync(
        IdentityTokenMigrationCheckpoint checkpoint,
        IIdentityTokenMigrationSource source,
        IIdentityTokenMigrationBatchProcessor processor,
        IIdentityTokenMigrationCheckpointStore checkpointStore,
        IdentityTokenMigrationOptions options,
        CancellationToken cancellationToken = default)
    {
        ValidateArguments(checkpoint, source, processor, checkpointStore, options);
        if (checkpoint.Stage != IdentityTokenMigrationStage.BackfillInProgress)
        {
            return Failure(IdentityTokenMigrationFailureCode.InvalidStageTransition);
        }

        if (!options.IsValid)
        {
            return Failure(IdentityTokenMigrationFailureCode.InvalidBatchSize);
        }

        if (await source.CountAsync(cancellationToken).ConfigureAwait(false) != checkpoint.ExpectedSourceRows)
        {
            return Failure(IdentityTokenMigrationFailureCode.SourceChanged);
        }

        IdentityTokenMigrationCheckpoint current = checkpoint;
        while (current.SourceRowsScanned < current.ExpectedSourceRows)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int requested = (int)Math.Min(options.BatchSize, current.ExpectedSourceRows - current.SourceRowsScanned);
            IReadOnlyList<LegacyIdentityTokenMigrationRow> rows = await source.ReadBatchAsync(
                current.SourceRowsScanned,
                requested,
                cancellationToken).ConfigureAwait(false);
            if (rows.Count == 0 || rows.Count > requested)
            {
                return Failure(IdentityTokenMigrationFailureCode.SourceChanged);
            }

            IdentityTokenMigrationResult<int> processed = await processor.WriteOrVerifyBatchAsync(
                rows,
                cancellationToken).ConfigureAwait(false);
            if (!processed.IsSuccess)
            {
                return Failure(processed.FailureCode);
            }

            if (processed.Value != rows.Count)
            {
                return Failure(IdentityTokenMigrationFailureCode.IncompleteBatch);
            }

            IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint> advanced =
                IdentityTokenMigrationStateMachine.Advance(
                    current,
                    IdentityTokenMigrationStage.BackfillInProgress,
                    current.SourceRowsScanned + rows.Count,
                    current.TargetRowsReady + processed.Value,
                    current.TargetRowsVerified);
            if (!advanced.IsSuccess)
            {
                return advanced;
            }

            current = advanced.Value;
            await checkpointStore.SaveAsync(current, cancellationToken).ConfigureAwait(false);
        }

        if (await source.CountAsync(cancellationToken).ConfigureAwait(false) != current.ExpectedSourceRows)
        {
            return Failure(IdentityTokenMigrationFailureCode.SourceChanged);
        }

        IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint> completed =
            IdentityTokenMigrationStateMachine.Advance(
                current,
                IdentityTokenMigrationStage.BackfillComplete,
                current.SourceRowsScanned,
                current.TargetRowsReady,
                current.TargetRowsVerified);
        if (!completed.IsSuccess)
        {
            return completed;
        }

        await checkpointStore.SaveAsync(completed.Value, cancellationToken).ConfigureAwait(false);
        return completed;
    }

    /// <summary>Fully verifies all remaining rows and records progress after each completed batch.</summary>
    public static async ValueTask<IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint>> VerifyAsync(
        IdentityTokenMigrationCheckpoint checkpoint,
        IIdentityTokenMigrationSource source,
        IIdentityTokenMigrationBatchProcessor processor,
        IIdentityTokenMigrationCheckpointStore checkpointStore,
        IdentityTokenMigrationOptions options,
        CancellationToken cancellationToken = default)
    {
        ValidateArguments(checkpoint, source, processor, checkpointStore, options);
        if (checkpoint.Stage is not (IdentityTokenMigrationStage.BackfillComplete or
            IdentityTokenMigrationStage.VerificationInProgress))
        {
            return Failure(IdentityTokenMigrationFailureCode.InvalidStageTransition);
        }

        if (!options.IsValid)
        {
            return Failure(IdentityTokenMigrationFailureCode.InvalidBatchSize);
        }

        if (await source.CountAsync(cancellationToken).ConfigureAwait(false) != checkpoint.ExpectedSourceRows)
        {
            return Failure(IdentityTokenMigrationFailureCode.SourceChanged);
        }

        IdentityTokenMigrationCheckpoint current = checkpoint;
        if (current.Stage == IdentityTokenMigrationStage.BackfillComplete)
        {
            IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint> started =
                IdentityTokenMigrationStateMachine.Advance(
                    current,
                    IdentityTokenMigrationStage.VerificationInProgress,
                    current.SourceRowsScanned,
                    current.TargetRowsReady,
                    current.TargetRowsVerified);
            if (!started.IsSuccess)
            {
                return started;
            }

            current = started.Value;
            await checkpointStore.SaveAsync(current, cancellationToken).ConfigureAwait(false);
        }

        while (current.TargetRowsVerified < current.ExpectedSourceRows)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int requested = (int)Math.Min(options.BatchSize, current.ExpectedSourceRows - current.TargetRowsVerified);
            IReadOnlyList<LegacyIdentityTokenMigrationRow> rows = await source.ReadBatchAsync(
                current.TargetRowsVerified,
                requested,
                cancellationToken).ConfigureAwait(false);
            if (rows.Count == 0 || rows.Count > requested)
            {
                return Failure(IdentityTokenMigrationFailureCode.SourceChanged);
            }

            IdentityTokenMigrationResult<int> verified = await processor.VerifyBatchAsync(
                rows,
                cancellationToken).ConfigureAwait(false);
            if (!verified.IsSuccess)
            {
                return Failure(verified.FailureCode);
            }

            if (verified.Value != rows.Count)
            {
                return Failure(IdentityTokenMigrationFailureCode.IncompleteBatch);
            }

            IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint> advanced =
                IdentityTokenMigrationStateMachine.Advance(
                    current,
                    IdentityTokenMigrationStage.VerificationInProgress,
                    current.SourceRowsScanned,
                    current.TargetRowsReady,
                    current.TargetRowsVerified + verified.Value);
            if (!advanced.IsSuccess)
            {
                return advanced;
            }

            current = advanced.Value;
            await checkpointStore.SaveAsync(current, cancellationToken).ConfigureAwait(false);
        }

        if (await source.CountAsync(cancellationToken).ConfigureAwait(false) != current.ExpectedSourceRows)
        {
            return Failure(IdentityTokenMigrationFailureCode.SourceChanged);
        }

        IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint> completed =
            IdentityTokenMigrationStateMachine.Advance(
                current,
                IdentityTokenMigrationStage.Verified,
                current.SourceRowsScanned,
                current.TargetRowsReady,
                current.TargetRowsVerified);
        if (!completed.IsSuccess)
        {
            return completed;
        }

        await checkpointStore.SaveAsync(completed.Value, cancellationToken).ConfigureAwait(false);
        return completed;
    }

    /// <summary>Verifies every migrated row through the generated runtime Identity lookup after cutover.</summary>
    public static async ValueTask<IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint>> VerifyRuntimeStoreAsync(
        IdentityTokenMigrationCheckpoint checkpoint,
        IIdentityTokenMigrationSource retainedLegacySource,
        IIdentityTokenMigrationRuntimeVerifier runtimeVerifier,
        IIdentityTokenMigrationCheckpointStore checkpointStore,
        IdentityTokenMigrationOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);
        ArgumentNullException.ThrowIfNull(retainedLegacySource);
        ArgumentNullException.ThrowIfNull(runtimeVerifier);
        ArgumentNullException.ThrowIfNull(checkpointStore);
        ArgumentNullException.ThrowIfNull(options);
        if (checkpoint.Stage != IdentityTokenMigrationStage.CutoverComplete)
        {
            return Failure(IdentityTokenMigrationFailureCode.InvalidStageTransition);
        }

        if (!options.IsValid)
        {
            return Failure(IdentityTokenMigrationFailureCode.InvalidBatchSize);
        }

        if (await retainedLegacySource.CountAsync(cancellationToken).ConfigureAwait(false) !=
            checkpoint.ExpectedSourceRows)
        {
            return Failure(IdentityTokenMigrationFailureCode.SourceChanged);
        }

        long offset = 0;
        while (offset < checkpoint.ExpectedSourceRows)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int requested = (int)Math.Min(options.BatchSize, checkpoint.ExpectedSourceRows - offset);
            IReadOnlyList<LegacyIdentityTokenMigrationRow> rows = await retainedLegacySource.ReadBatchAsync(
                offset,
                requested,
                cancellationToken).ConfigureAwait(false);
            if (rows.Count == 0 || rows.Count > requested)
            {
                return Failure(IdentityTokenMigrationFailureCode.SourceChanged);
            }

            IdentityTokenMigrationResult<int> verified = await runtimeVerifier.VerifyBatchAsync(
                rows,
                cancellationToken).ConfigureAwait(false);
            if (!verified.IsSuccess)
            {
                return Failure(verified.FailureCode);
            }

            if (verified.Value != rows.Count)
            {
                return Failure(IdentityTokenMigrationFailureCode.IncompleteBatch);
            }

            offset += rows.Count;
        }

        if (await retainedLegacySource.CountAsync(cancellationToken).ConfigureAwait(false) !=
            checkpoint.ExpectedSourceRows)
        {
            return Failure(IdentityTokenMigrationFailureCode.SourceChanged);
        }

        IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint> completed =
            IdentityTokenMigrationStateMachine.Advance(
                checkpoint,
                IdentityTokenMigrationStage.RuntimeVerified,
                checkpoint.SourceRowsScanned,
                checkpoint.TargetRowsReady,
                checkpoint.TargetRowsVerified);
        if (completed.IsSuccess)
        {
            await checkpointStore.SaveAsync(completed.Value, cancellationToken).ConfigureAwait(false);
        }

        return completed;
    }

    /// <summary>Durably records that application writes may begin after runtime verification succeeds.</summary>
    public static async ValueTask<IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint>> AcceptProtectedWritesAsync(
        IdentityTokenMigrationCheckpoint checkpoint,
        IIdentityTokenMigrationCheckpointStore checkpointStore,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);
        ArgumentNullException.ThrowIfNull(checkpointStore);
        IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint> accepted =
            IdentityTokenMigrationStateMachine.AcceptProtectedWrites(checkpoint);
        if (accepted.IsSuccess)
        {
            await checkpointStore.SaveAsync(accepted.Value, cancellationToken).ConfigureAwait(false);
        }

        return accepted;
    }

    private static void ValidateArguments(
        IdentityTokenMigrationCheckpoint checkpoint,
        IIdentityTokenMigrationSource source,
        IIdentityTokenMigrationBatchProcessor processor,
        IIdentityTokenMigrationCheckpointStore checkpointStore,
        IdentityTokenMigrationOptions options)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(processor);
        ArgumentNullException.ThrowIfNull(checkpointStore);
        ArgumentNullException.ThrowIfNull(options);
    }

    private static IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint> Failure(
        IdentityTokenMigrationFailureCode code) =>
        IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint>.Failure(code);
}
