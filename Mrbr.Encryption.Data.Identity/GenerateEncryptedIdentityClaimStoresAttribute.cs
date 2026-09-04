namespace Mrbr.Encryption.Data.Identity;

/// <summary>Selects composite keyed routing for protected user and role claims.</summary>
[AttributeUsage(AttributeTargets.Class, AllowMultiple = false, Inherited = false)]
public sealed class GenerateEncryptedIdentityClaimStoresAttribute : Attribute
{
    /// <summary>Initializes the marker with the logical source key used for claim routing HMACs.</summary>
    public GenerateEncryptedIdentityClaimStoresAttribute(string sourceKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourceKey);
        SourceKey = sourceKey;
    }

    /// <summary>Gets the logical source key used for claim routing HMACs.</summary>
    public string SourceKey { get; }
}
