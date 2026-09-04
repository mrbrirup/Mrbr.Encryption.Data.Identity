using Microsoft.AspNetCore.Identity;

namespace Mrbr.Encryption.Data.Identity;

/// <summary>
/// Performs source-generated, collision-verifying searches for protected Identity users.
/// </summary>
/// <typeparam name="TUser">The application Identity user type.</typeparam>
public interface IEncryptedIdentityUserLookup<TUser> : IEncryptedIdentityUserLookup<string, TUser>
    where TUser : IdentityUser
{
}

/// <summary>Performs protected Identity user lookups for an application-selected key type.</summary>
public interface IEncryptedIdentityUserLookup<TKey, TUser>
    where TKey : IEquatable<TKey>
    where TUser : IdentityUser<TKey>
{
    /// <summary>
    /// Finds every verified plaintext match for a normalized username.
    /// </summary>
    Task<IReadOnlyList<TUser>> FindByNormalizedUserNameMatchesAsync(
        string normalizedUserName,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Finds every verified plaintext match for a normalized email address.
    /// </summary>
    Task<IReadOnlyList<TUser>> FindByNormalizedEmailMatchesAsync(
        string normalizedEmail,
        CancellationToken cancellationToken = default);
}
