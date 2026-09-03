namespace Mrbr.Encryption.Data.Identity.Migration;

/// <summary>One plaintext legacy token row held only for the lifetime of a migration batch.</summary>
public sealed class LegacyIdentityTokenMigrationRow
{
    /// <summary>Initializes one legacy Identity token row.</summary>
    public LegacyIdentityTokenMigrationRow(string userId, string loginProvider, string name, string? value)
    {
        ArgumentNullException.ThrowIfNull(userId);
        ArgumentNullException.ThrowIfNull(loginProvider);
        ArgumentNullException.ThrowIfNull(name);
        UserId = userId;
        LoginProvider = loginProvider;
        Name = name;
        Value = value;
    }

    /// <summary>Gets the plaintext user foreign key.</summary>
    public string UserId { get; }

    /// <summary>Gets the plaintext provider protocol identifier.</summary>
    public string LoginProvider { get; }

    /// <summary>Gets the plaintext token-name protocol identifier.</summary>
    public string Name { get; }

    /// <summary>Gets the nullable plaintext token value.</summary>
    public string? Value { get; }

    /// <summary>Returns a deliberately redacted representation.</summary>
    public override string ToString() => nameof(LegacyIdentityTokenMigrationRow);
}
