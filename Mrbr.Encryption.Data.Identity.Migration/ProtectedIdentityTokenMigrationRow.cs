namespace Mrbr.Encryption.Data.Identity.Migration;

/// <summary>One fully protected token row ready for provider persistence.</summary>
public sealed class ProtectedIdentityTokenMigrationRow
{
    /// <summary>Initializes one protected Identity token row.</summary>
    public ProtectedIdentityTokenMigrationRow(
        Guid tokenId,
        string userId,
        string encryptedLoginProvider,
        string encryptedName,
        string? encryptedValue,
        string routingHash)
    {
        ArgumentNullException.ThrowIfNull(userId);
        ArgumentNullException.ThrowIfNull(encryptedLoginProvider);
        ArgumentNullException.ThrowIfNull(encryptedName);
        ArgumentNullException.ThrowIfNull(routingHash);
        TokenId = tokenId;
        UserId = userId;
        EncryptedLoginProvider = encryptedLoginProvider;
        EncryptedName = encryptedName;
        EncryptedValue = encryptedValue;
        RoutingHash = routingHash;
    }

    /// <summary>Gets the application-generated UUIDv7 primary key.</summary>
    public Guid TokenId { get; }

    /// <summary>Gets the plaintext user foreign key.</summary>
    public string UserId { get; }

    /// <summary>Gets the protected provider value.</summary>
    public string EncryptedLoginProvider { get; }

    /// <summary>Gets the protected token-name value.</summary>
    public string EncryptedName { get; }

    /// <summary>Gets the nullable protected token value.</summary>
    public string? EncryptedValue { get; }

    /// <summary>Gets the keyed composite routing hash.</summary>
    public string RoutingHash { get; }

    /// <summary>Returns a deliberately redacted representation.</summary>
    public override string ToString() => nameof(ProtectedIdentityTokenMigrationRow);
}
