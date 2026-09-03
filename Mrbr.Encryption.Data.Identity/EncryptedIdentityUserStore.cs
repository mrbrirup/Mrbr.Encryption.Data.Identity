using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Mrbr.Encryption.Data.Identity;

/// <summary>
/// An Identity user store that routes username and email lookup through keyed-hash candidates
/// and source-generated plaintext collision verification.
/// </summary>
public class EncryptedIdentityUserStore<TUser, TRole, TContext> :
    UserStore<TUser, TRole, TContext>
    where TUser : IdentityUser
    where TRole : IdentityRole
    where TContext : DbContext
{
    private readonly IEncryptedIdentityUserLookup<TUser> lookup;

    /// <summary>
    /// Creates an encrypted Identity user store.
    /// </summary>
    public EncryptedIdentityUserStore(
        TContext context,
        IdentityErrorDescriber describer,
        IEncryptedIdentityUserLookup<TUser> lookup)
        : base(context, describer)
    {
        this.lookup = lookup ?? throw new ArgumentNullException(nameof(lookup));
    }

    /// <inheritdoc />
    public override async Task<TUser?> FindByNameAsync(
        string normalizedUserName,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(normalizedUserName);
        IReadOnlyList<TUser> matches = await lookup
            .FindByNormalizedUserNameMatchesAsync(normalizedUserName, cancellationToken)
            .ConfigureAwait(false);

        return GetSingleVerifiedMatch(matches, nameof(normalizedUserName));
    }

    /// <inheritdoc />
    public override async Task<TUser?> FindByEmailAsync(
        string normalizedEmail,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(normalizedEmail);
        IReadOnlyList<TUser> matches = await lookup
            .FindByNormalizedEmailMatchesAsync(normalizedEmail, cancellationToken)
            .ConfigureAwait(false);

        return GetSingleVerifiedMatch(matches, nameof(normalizedEmail));
    }

    private static TUser? GetSingleVerifiedMatch(
        IReadOnlyList<TUser> matches,
        string lookupName)
    {
        ArgumentNullException.ThrowIfNull(matches);

        return matches.Count switch
        {
            0 => null,
            1 => matches[0],
            _ => throw new InvalidOperationException(
                $"Identity lookup '{lookupName}' produced multiple verified plaintext matches.")
        };
    }
}
