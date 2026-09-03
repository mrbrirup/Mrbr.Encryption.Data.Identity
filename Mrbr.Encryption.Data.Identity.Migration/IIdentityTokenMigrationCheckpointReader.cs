namespace Mrbr.Encryption.Data.Identity.Migration;

/// <summary>Loads a previously persisted, non-secret migration checkpoint.</summary>
public interface IIdentityTokenMigrationCheckpointReader
{
    /// <summary>Loads and validates a checkpoint, or returns a successful null result when it does not exist.</summary>
    ValueTask<IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint?>> LoadAsync(
        Guid migrationId,
        CancellationToken cancellationToken);
}
