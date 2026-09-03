namespace Mrbr.Encryption.Data.Identity.Migration;

/// <summary>Identifies a durable stage of an explicit Identity token migration.</summary>
public enum IdentityTokenMigrationStage
{
    /// <summary>The migration manifest has been created but no database work has occurred.</summary>
    Created = 0,
    /// <summary>Configuration, keys, permissions, schema, backup and maintenance controls passed preflight.</summary>
    PreflightPassed = 1,
    /// <summary>The protected shadow table and temporary constraints have been created.</summary>
    ShadowSchemaCreated = 2,
    /// <summary>Legacy rows are being copied into the protected shadow table in committed batches.</summary>
    BackfillInProgress = 3,
    /// <summary>Every source row has a corresponding protected target row.</summary>
    BackfillComplete = 4,
    /// <summary>Protected target rows are being decrypted and compared with their frozen source rows.</summary>
    VerificationInProgress = 5,
    /// <summary>Counts, routing hashes and decrypted plaintext comparisons have all been verified.</summary>
    Verified = 6,
    /// <summary>The protected table has been placed at the application's expected table name.</summary>
    CutoverComplete = 7,
    /// <summary>The generated runtime Identity store has verified every migrated logical row after cutover.</summary>
    RuntimeVerified = 8,
    /// <summary>The retained plaintext table has been deliberately removed.</summary>
    PlaintextRemoved = 9,
    /// <summary>The pre-write cutover was reversed and this migration execution is terminal.</summary>
    RolledBack = 10
}
