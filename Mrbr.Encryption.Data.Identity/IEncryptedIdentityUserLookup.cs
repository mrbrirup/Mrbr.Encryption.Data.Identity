using Microsoft.AspNetCore.Identity;

namespace Mrbr.Encryption.Data.Identity;

/// <summary>
/// Performs source-generated, collision-verifying searches for protected Identity users.
/// </summary>
/// <typeparam name="TUser">The application Identity user type.</typeparam>
public interface IEncryptedIdentityUserLookup<TUser>
    where TUser : IdentityUser
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
