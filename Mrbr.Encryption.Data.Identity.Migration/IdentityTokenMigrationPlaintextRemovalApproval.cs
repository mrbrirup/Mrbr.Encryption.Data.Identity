namespace Mrbr.Encryption.Data.Identity.Migration;

/// <summary>Records the operator's explicit acknowledgements for irreversible retained-plaintext removal.</summary>
public sealed class IdentityTokenMigrationPlaintextRemovalApproval
{
    /// <summary>Initializes the acknowledgements for one migration execution.</summary>
    public IdentityTokenMigrationPlaintextRemovalApproval(
        Guid migrationId,
        bool backupRetentionAddressed,
        bool replicasAndExportsAddressed,
        bool irreversibleRemovalApproved)
    {
        MigrationId = migrationId;
        BackupRetentionAddressed = backupRetentionAddressed;
        ReplicasAndExportsAddressed = replicasAndExportsAddressed;
        IrreversibleRemovalApproved = irreversibleRemovalApproved;
    }

    /// <summary>Gets the migration execution being approved.</summary>
    public Guid MigrationId { get; }

    /// <summary>Gets whether backups and WAL retention containing plaintext have been addressed.</summary>
    public bool BackupRetentionAddressed { get; }

    /// <summary>Gets whether replicas, exports and snapshots containing plaintext have been addressed.</summary>
    public bool ReplicasAndExportsAddressed { get; }

    /// <summary>Gets whether irreversible deletion of the retained table is explicitly approved.</summary>
    public bool IrreversibleRemovalApproved { get; }

    /// <summary>Returns whether every acknowledgement applies to the supplied UUIDv7 migration.</summary>
    public bool IsApprovedFor(Guid migrationId) =>
        MigrationId == migrationId &&
        migrationId != Guid.Empty &&
        migrationId.Version == 7 &&
        BackupRetentionAddressed &&
        ReplicasAndExportsAddressed &&
        IrreversibleRemovalApproved;
}
