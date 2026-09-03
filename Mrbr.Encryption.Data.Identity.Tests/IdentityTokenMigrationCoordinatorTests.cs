using Mrbr.Encryption.Data.Identity.Migration;

namespace Mrbr.Encryption.Data.Identity.Tests;

public sealed class IdentityTokenMigrationCoordinatorTests
{
    [Fact]
    public async Task Backfill_CommitsBoundedBatchesAndCompletes()
    {
        FakeSource source = new(CreateRows(5));
        FakeProcessor processor = new();
        FakeCheckpointStore checkpoints = new();
        IdentityTokenMigrationCheckpoint start = MoveToBackfill(5);

        var result = await IdentityTokenMigrationCoordinator.BackfillAsync(
            start,
            source,
            processor,
            checkpoints,
            new IdentityTokenMigrationOptions { BatchSize = 2 });

        IdentityTokenMigrationCheckpoint completed = AssertSuccess(result);
        Assert.Equal(IdentityTokenMigrationStage.BackfillComplete, completed.Stage);
        Assert.Equal([0L, 2L, 4L], source.Offsets);
        Assert.Equal([2, 2, 1], processor.WrittenBatchSizes);
        Assert.Equal(4, checkpoints.Saved.Count);
        Assert.Equal(5, completed.TargetRowsReady);
    }

    [Fact]
    public async Task Backfill_ResumesFromNonSecretAggregateOffset()
    {
        FakeSource source = new(CreateRows(5));
        FakeProcessor processor = new();
        FakeCheckpointStore checkpoints = new();
        IdentityTokenMigrationCheckpoint start = MoveToBackfill(5);
        start = AssertSuccess(IdentityTokenMigrationStateMachine.Advance(
            start,
            IdentityTokenMigrationStage.BackfillInProgress,
            2,
            2,
            0));

        IdentityTokenMigrationCheckpoint completed = AssertSuccess(
            await IdentityTokenMigrationCoordinator.BackfillAsync(
                start,
                source,
                processor,
                checkpoints,
                new IdentityTokenMigrationOptions { BatchSize = 2 }));

        Assert.Equal([2L, 4L], source.Offsets);
        Assert.Equal(5, completed.SourceRowsScanned);
    }

    [Fact]
    public async Task Backfill_PropagatesKnownProcessorFailureWithoutSavingFalseProgress()
    {
        FakeSource source = new(CreateRows(2));
        FakeProcessor processor = new(IdentityTokenMigrationFailureCode.KeyUnavailable);
        FakeCheckpointStore checkpoints = new();

        var result = await IdentityTokenMigrationCoordinator.BackfillAsync(
            MoveToBackfill(2),
            source,
            processor,
            checkpoints,
            new IdentityTokenMigrationOptions());

        Assert.False(result.IsSuccess);
        Assert.Equal(IdentityTokenMigrationFailureCode.KeyUnavailable, result.FailureCode);
        Assert.Empty(checkpoints.Saved);
    }

    [Fact]
    public async Task Backfill_RejectsChangedSourceBeforeReadingPlaintext()
    {
        FakeSource source = new(CreateRows(3));
        FakeProcessor processor = new();

        var result = await IdentityTokenMigrationCoordinator.BackfillAsync(
            MoveToBackfill(2),
            source,
            processor,
            new FakeCheckpointStore(),
            new IdentityTokenMigrationOptions());

        Assert.False(result.IsSuccess);
        Assert.Equal(IdentityTokenMigrationFailureCode.SourceChanged, result.FailureCode);
        Assert.Empty(source.Offsets);
    }

    [Fact]
    public async Task Verify_IsResumableAndRequiresEveryRow()
    {
        FakeSource source = new(CreateRows(5));
        FakeProcessor processor = new();
        FakeCheckpointStore checkpoints = new();
        IdentityTokenMigrationCheckpoint start = MoveToBackfillComplete(5);

        IdentityTokenMigrationCheckpoint completed = AssertSuccess(
            await IdentityTokenMigrationCoordinator.VerifyAsync(
                start,
                source,
                processor,
                checkpoints,
                new IdentityTokenMigrationOptions { BatchSize = 2 }));

        Assert.Equal(IdentityTokenMigrationStage.Verified, completed.Stage);
        Assert.Equal(5, completed.TargetRowsVerified);
        Assert.Equal([0L, 2L, 4L], source.Offsets);
        Assert.Equal([2, 2, 1], processor.VerifiedBatchSizes);
        Assert.Equal(5, checkpoints.Saved.Count);
    }

    [Fact]
    public async Task RuntimeVerification_ReadsEveryRetainedRowInBoundedBatchesAndSavesGate()
    {
        FakeSource source = new(CreateRows(5));
        FakeRuntimeVerifier verifier = new();
        FakeCheckpointStore checkpoints = new();

        IdentityTokenMigrationCheckpoint completed = AssertSuccess(
            await IdentityTokenMigrationCoordinator.VerifyRuntimeStoreAsync(
                MoveToCutoverComplete(5),
                source,
                verifier,
                checkpoints,
                new IdentityTokenMigrationOptions { BatchSize = 2 }));

        Assert.Equal(IdentityTokenMigrationStage.RuntimeVerified, completed.Stage);
        Assert.False(completed.ProtectedWritesAccepted);
        Assert.Equal([0L, 2L, 4L], source.Offsets);
        Assert.Equal([2, 2, 1], verifier.BatchSizes);
        Assert.Single(checkpoints.Saved);
        Assert.Same(completed, checkpoints.Saved[0]);
    }

    [Fact]
    public async Task RuntimeVerification_PropagatesKnownFailureWithoutOpeningWriteGate()
    {
        FakeCheckpointStore checkpoints = new();

        var result = await IdentityTokenMigrationCoordinator.VerifyRuntimeStoreAsync(
            MoveToCutoverComplete(2),
            new FakeSource(CreateRows(2)),
            new FakeRuntimeVerifier(IdentityTokenMigrationFailureCode.AuthenticationFailed),
            checkpoints,
            new IdentityTokenMigrationOptions());

        Assert.False(result.IsSuccess);
        Assert.Equal(IdentityTokenMigrationFailureCode.AuthenticationFailed, result.FailureCode);
        Assert.Empty(checkpoints.Saved);
    }

    [Fact]
    public async Task RuntimeVerification_RejectsChangedRetainedSourceBeforeReadingPlaintext()
    {
        FakeSource source = new(CreateRows(3));

        var result = await IdentityTokenMigrationCoordinator.VerifyRuntimeStoreAsync(
            MoveToCutoverComplete(2),
            source,
            new FakeRuntimeVerifier(),
            new FakeCheckpointStore(),
            new IdentityTokenMigrationOptions());

        Assert.False(result.IsSuccess);
        Assert.Equal(IdentityTokenMigrationFailureCode.SourceChanged, result.FailureCode);
        Assert.Empty(source.Offsets);
    }

    [Fact]
    public async Task AcceptProtectedWrites_RequiresRuntimeVerificationAndSavesBoundary()
    {
        FakeCheckpointStore rejectedStore = new();
        var rejected = await IdentityTokenMigrationCoordinator.AcceptProtectedWritesAsync(
            MoveToCutoverComplete(1),
            rejectedStore);
        Assert.False(rejected.IsSuccess);
        Assert.Equal(IdentityTokenMigrationFailureCode.InvalidStageTransition, rejected.FailureCode);
        Assert.Empty(rejectedStore.Saved);

        IdentityTokenMigrationCheckpoint verified = AssertSuccess(
            IdentityTokenMigrationStateMachine.Advance(
                MoveToCutoverComplete(1),
                IdentityTokenMigrationStage.RuntimeVerified,
                1,
                1,
                1));
        FakeCheckpointStore acceptedStore = new();
        IdentityTokenMigrationCheckpoint accepted = AssertSuccess(
            await IdentityTokenMigrationCoordinator.AcceptProtectedWritesAsync(verified, acceptedStore));

        Assert.True(accepted.ProtectedWritesAccepted);
        Assert.Single(acceptedStore.Saved);
        Assert.Same(accepted, acceptedStore.Saved[0]);
    }

    [Fact]
    public async Task InvalidBatchSizeReturnsKnownFailure()
    {
        var result = await IdentityTokenMigrationCoordinator.BackfillAsync(
            MoveToBackfill(0),
            new FakeSource([]),
            new FakeProcessor(),
            new FakeCheckpointStore(),
            new IdentityTokenMigrationOptions { BatchSize = 0 });

        Assert.False(result.IsSuccess);
        Assert.Equal(IdentityTokenMigrationFailureCode.InvalidBatchSize, result.FailureCode);
    }

    [Fact]
    public void LegacyRowStringRepresentationDoesNotLeakProtectedValues()
    {
        LegacyIdentityTokenMigrationRow row = new("user-secret", "provider-secret", "name-secret", "value-secret");

        string text = row.ToString();

        Assert.Equal(nameof(LegacyIdentityTokenMigrationRow), text);
        Assert.DoesNotContain("secret", text, StringComparison.Ordinal);
    }

    private static IReadOnlyList<LegacyIdentityTokenMigrationRow> CreateRows(int count) =>
        Enumerable.Range(0, count)
            .Select(index => new LegacyIdentityTokenMigrationRow(
                "user-" + index,
                "provider-" + index,
                "name-" + index,
                "value-" + index))
            .ToArray();

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

    private static IdentityTokenMigrationCheckpoint MoveToBackfillComplete(long expectedRows)
    {
        IdentityTokenMigrationCheckpoint checkpoint = MoveToBackfill(expectedRows);
        return AssertSuccess(IdentityTokenMigrationStateMachine.Advance(
            checkpoint,
            IdentityTokenMigrationStage.BackfillComplete,
            expectedRows,
            expectedRows,
            0));
    }

    private static IdentityTokenMigrationCheckpoint MoveToCutoverComplete(long expectedRows)
    {
        IdentityTokenMigrationCheckpoint checkpoint = MoveToBackfillComplete(expectedRows);
        checkpoint = AssertSuccess(IdentityTokenMigrationStateMachine.Advance(
            checkpoint,
            IdentityTokenMigrationStage.VerificationInProgress,
            expectedRows,
            expectedRows,
            0));
        checkpoint = AssertSuccess(IdentityTokenMigrationStateMachine.Advance(
            checkpoint,
            IdentityTokenMigrationStage.Verified,
            expectedRows,
            expectedRows,
            expectedRows));
        return AssertSuccess(IdentityTokenMigrationStateMachine.Advance(
            checkpoint,
            IdentityTokenMigrationStage.CutoverComplete,
            expectedRows,
            expectedRows,
            expectedRows));
    }

    private static T AssertSuccess<T>(IdentityTokenMigrationResult<T> result)
    {
        Assert.True(result.IsSuccess, $"Expected success, received {result.FailureCode}.");
        return result.Value;
    }

    private sealed class FakeSource(IReadOnlyList<LegacyIdentityTokenMigrationRow> rows)
        : IIdentityTokenMigrationSource
    {
        public List<long> Offsets { get; } = [];

        public ValueTask<long> CountAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult((long)rows.Count);

        public ValueTask<IReadOnlyList<LegacyIdentityTokenMigrationRow>> ReadBatchAsync(
            long offset,
            int batchSize,
            CancellationToken cancellationToken)
        {
            Offsets.Add(offset);
            IReadOnlyList<LegacyIdentityTokenMigrationRow> batch = rows
                .Skip(checked((int)offset))
                .Take(batchSize)
                .ToArray();
            return ValueTask.FromResult(batch);
        }
    }

    private sealed class FakeProcessor(
        IdentityTokenMigrationFailureCode failureCode = IdentityTokenMigrationFailureCode.None)
        : IIdentityTokenMigrationBatchProcessor
    {
        public List<int> WrittenBatchSizes { get; } = [];

        public List<int> VerifiedBatchSizes { get; } = [];

        public ValueTask<IdentityTokenMigrationResult<int>> WriteOrVerifyBatchAsync(
            IReadOnlyList<LegacyIdentityTokenMigrationRow> sourceRows,
            CancellationToken cancellationToken)
        {
            WrittenBatchSizes.Add(sourceRows.Count);
            return ValueTask.FromResult(Result(sourceRows.Count));
        }

        public ValueTask<IdentityTokenMigrationResult<int>> VerifyBatchAsync(
            IReadOnlyList<LegacyIdentityTokenMigrationRow> sourceRows,
            CancellationToken cancellationToken)
        {
            VerifiedBatchSizes.Add(sourceRows.Count);
            return ValueTask.FromResult(Result(sourceRows.Count));
        }

        private IdentityTokenMigrationResult<int> Result(int count) =>
            failureCode == IdentityTokenMigrationFailureCode.None
                ? IdentityTokenMigrationResult<int>.Success(count)
                : IdentityTokenMigrationResult<int>.Failure(failureCode);
    }

    private sealed class FakeCheckpointStore : IIdentityTokenMigrationCheckpointStore
    {
        public List<IdentityTokenMigrationCheckpoint> Saved { get; } = [];

        public ValueTask SaveAsync(
            IdentityTokenMigrationCheckpoint checkpoint,
            CancellationToken cancellationToken)
        {
            Saved.Add(checkpoint);
            return ValueTask.CompletedTask;
        }
    }

    private sealed class FakeRuntimeVerifier(
        IdentityTokenMigrationFailureCode failureCode = IdentityTokenMigrationFailureCode.None)
        : IIdentityTokenMigrationRuntimeVerifier
    {
        public List<int> BatchSizes { get; } = [];

        public ValueTask<IdentityTokenMigrationResult<int>> VerifyBatchAsync(
            IReadOnlyList<LegacyIdentityTokenMigrationRow> sourceRows,
            CancellationToken cancellationToken)
        {
            BatchSizes.Add(sourceRows.Count);
            return ValueTask.FromResult(
                failureCode == IdentityTokenMigrationFailureCode.None
                    ? IdentityTokenMigrationResult<int>.Success(sourceRows.Count)
                    : IdentityTokenMigrationResult<int>.Failure(failureCode));
        }
    }
}
