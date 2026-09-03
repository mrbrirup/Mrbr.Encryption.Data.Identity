namespace Mrbr.Encryption.Data.Identity;

/// <summary>Requests generated protected Identity token persistence for a database context.</summary>
[AttributeUsage(AttributeTargets.Class, AllowMultiple = false, Inherited = false)]
public sealed class GenerateEncryptedIdentityTokenStoreAttribute : Attribute
{
    /// <summary>Initializes the marker with the logical source key used for token routing HMACs.</summary>
    public GenerateEncryptedIdentityTokenStoreAttribute(string sourceKey)
    {
        SourceKey = string.IsNullOrWhiteSpace(sourceKey)
            ? throw new ArgumentException("A source key is required.", nameof(sourceKey))
            : sourceKey;
    }

    /// <summary>Gets the logical source key used for token routing HMACs.</summary>
    public string SourceKey { get; }
}
