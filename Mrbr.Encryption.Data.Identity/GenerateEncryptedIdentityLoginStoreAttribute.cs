namespace Mrbr.Encryption.Data.Identity;

/// <summary>Selects protected external-login persistence for an Identity context.</summary>
[AttributeUsage(AttributeTargets.Class, AllowMultiple = false, Inherited = false)]
public sealed class GenerateEncryptedIdentityLoginStoreAttribute : Attribute
{
    /// <summary>Initializes the marker with the logical source key used for external-login routing.</summary>
    public GenerateEncryptedIdentityLoginStoreAttribute(string sourceKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourceKey);
        SourceKey = sourceKey;
    }

    /// <summary>Gets the logical source key used for external-login routing.</summary>
    public string SourceKey { get; }
}
