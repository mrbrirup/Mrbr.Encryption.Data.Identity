using Microsoft.AspNetCore.Identity;

namespace Mrbr.Encryption.Data.Identity;

/// <summary>Performs source-generated, collision-verifying searches for protected Identity roles.</summary>
public interface IEncryptedIdentityRoleLookup<TRole> : IEncryptedIdentityRoleLookup<string, TRole>
    where TRole : IdentityRole
{
}

/// <summary>Performs protected Identity role lookups for an application-selected key type.</summary>
public interface IEncryptedIdentityRoleLookup<TKey, TRole>
    where TKey : IEquatable<TKey>
    where TRole : IdentityRole<TKey>
{
    /// <summary>Finds every verified plaintext match for a normalized role name.</summary>
    Task<IReadOnlyList<TRole>> FindByNormalizedNameMatchesAsync(
        string normalizedName,
        CancellationToken cancellationToken = default);
}
