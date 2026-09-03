namespace Mrbr.Encryption.Data.Identity.Migration;

/// <summary>Reads a frozen legacy token table in complete composite-key order.</summary>
public interface IIdentityTokenMigrationSource
{
    /// <summary>Returns the current number of frozen source rows.</summary>
    ValueTask<long> CountAsync(CancellationToken cancellationToken);

    /// <summary>Reads a bounded page using a non-secret numeric offset.</summary>
    ValueTask<IReadOnlyList<LegacyIdentityTokenMigrationRow>> ReadBatchAsync(
        long offset,
        int batchSize,
        CancellationToken cancellationToken);
}
