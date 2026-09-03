namespace Mrbr.Encryption.Data.Identity.Migration;

/// <summary>Durably stores a non-secret checkpoint after its corresponding database batch commits.</summary>
public interface IIdentityTokenMigrationCheckpointStore
{
    /// <summary>Saves the complete immutable checkpoint.</summary>
    ValueTask SaveAsync(IdentityTokenMigrationCheckpoint checkpoint, CancellationToken cancellationToken);
}
