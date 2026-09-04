namespace Mrbr.Encryption.Data.Identity;

/// <summary>Selects protected passkey persistence for an Identity context.</summary>
[AttributeUsage(AttributeTargets.Class, AllowMultiple = false, Inherited = false)]
public sealed class GenerateEncryptedIdentityPasskeyStoreAttribute : Attribute
{
    /// <summary>Initializes the marker with the logical credential lookup source key.</summary>
    public GenerateEncryptedIdentityPasskeyStoreAttribute(string sourceKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourceKey);
        SourceKey = sourceKey;
    }

    /// <summary>Gets the logical credential lookup source key.</summary>
    public string SourceKey { get; }
}
