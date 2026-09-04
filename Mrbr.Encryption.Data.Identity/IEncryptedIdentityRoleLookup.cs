using Microsoft.AspNetCore.Identity;

namespace Mrbr.Encryption.Data.Identity;

/// <summary>Performs source-generated, collision-verifying searches for protected Identity roles.</summary>
public interface IEncryptedIdentityRoleLookup<TRole>
    where TRole : IdentityRole
{
    /// <summary>Finds every verified plaintext match for a normalized role name.</summary>
    Task<IReadOnlyList<TRole>> FindByNormalizedNameMatchesAsync(
        string normalizedName,
        CancellationToken cancellationToken = default);
}
