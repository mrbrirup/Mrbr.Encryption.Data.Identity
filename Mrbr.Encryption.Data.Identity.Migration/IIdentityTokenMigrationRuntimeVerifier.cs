namespace Mrbr.Encryption.Data.Identity.Migration;

/// <summary>Uses the generated runtime Identity model and store path to verify migrated logical rows after cutover.</summary>
public interface IIdentityTokenMigrationRuntimeVerifier
{
    /// <summary>Verifies one bounded batch through the application's generated runtime token lookup.</summary>
    ValueTask<IdentityTokenMigrationResult<int>> VerifyBatchAsync(
        IReadOnlyList<LegacyIdentityTokenMigrationRow> sourceRows,
        CancellationToken cancellationToken);
}
