namespace Mrbr.Encryption.Data.Identity.Migration;

/// <summary>An immutable, non-secret checkpoint suitable for durable migration storage.</summary>
public sealed class IdentityTokenMigrationCheckpoint
{
    internal IdentityTokenMigrationCheckpoint(
        Guid migrationId,
        IdentityTokenMigrationStage stage,
        long expectedSourceRows,
        long sourceRowsScanned,
        long targetRowsReady,
        long targetRowsVerified,
        bool protectedWritesAccepted)
    {
        MigrationId = migrationId;
        Stage = stage;
        ExpectedSourceRows = expectedSourceRows;
        SourceRowsScanned = sourceRowsScanned;
        TargetRowsReady = targetRowsReady;
        TargetRowsVerified = targetRowsVerified;
        ProtectedWritesAccepted = protectedWritesAccepted;
    }

    /// <summary>Gets the UUIDv7 identifier for one deliberate migration execution.</summary>
    public Guid MigrationId { get; }

    /// <summary>Gets the last durably completed stage.</summary>
    public IdentityTokenMigrationStage Stage { get; }

    /// <summary>Gets the source row count captured while token mutations were disabled.</summary>
    public long ExpectedSourceRows { get; }

    /// <summary>Gets the number of legacy rows scanned in committed batches.</summary>
    public long SourceRowsScanned { get; }

    /// <summary>Gets the number of protected rows written or idempotently verified in the shadow table.</summary>
    public long TargetRowsReady { get; }

    /// <summary>Gets the number of target rows verified by decrypting and comparing all logical fields.</summary>
    public long TargetRowsVerified { get; }

    /// <summary>Gets whether application writes have been allowed against the protected table.</summary>
    public bool ProtectedWritesAccepted { get; }

    /// <summary>Gets whether a metadata-only table swap can still safely restore the legacy table.</summary>
    public bool CanRollbackByTableSwap =>
        Stage is IdentityTokenMigrationStage.CutoverComplete or IdentityTokenMigrationStage.RuntimeVerified &&
        !ProtectedWritesAccepted;
}
