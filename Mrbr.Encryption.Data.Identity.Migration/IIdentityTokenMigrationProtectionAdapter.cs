namespace Mrbr.Encryption.Data.Identity.Migration;

/// <summary>Application-generated protection logic bound to validated source-key configuration.</summary>
public interface IIdentityTokenMigrationProtectionAdapter
{
    /// <summary>Computes the canonical keyed composite route hash without creating encryption keys.</summary>
    IdentityTokenMigrationResult<string> ComputeRoutingHash(LegacyIdentityTokenMigrationRow sourceRow);

    /// <summary>Protects all sensitive fields using the supplied UUIDv7 and previously computed route hash.</summary>
    IdentityTokenMigrationResult<ProtectedIdentityTokenMigrationRow> Protect(
        LegacyIdentityTokenMigrationRow sourceRow,
        Guid tokenId,
        string routingHash);

    /// <summary>Decrypts, recomputes and ordinally compares every logical field.</summary>
    IdentityTokenMigrationResult<bool> Verify(
        LegacyIdentityTokenMigrationRow sourceRow,
        ProtectedIdentityTokenMigrationRow targetRow);
}
