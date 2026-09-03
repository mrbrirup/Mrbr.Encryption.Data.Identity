namespace Mrbr.Encryption.Data.Identity.Migration;

/// <summary>Protects, writes and idempotently verifies batches through generated application configuration.</summary>
public interface IIdentityTokenMigrationBatchProcessor
{
    /// <summary>Writes protected rows or fully verifies matching rows committed by an earlier run.</summary>
    ValueTask<IdentityTokenMigrationResult<int>> WriteOrVerifyBatchAsync(
        IReadOnlyList<LegacyIdentityTokenMigrationRow> sourceRows,
        CancellationToken cancellationToken);

    /// <summary>Decrypts and compares every protected field and recomputes every route hash in the batch.</summary>
    ValueTask<IdentityTokenMigrationResult<int>> VerifyBatchAsync(
        IReadOnlyList<LegacyIdentityTokenMigrationRow> sourceRows,
        CancellationToken cancellationToken);
}
