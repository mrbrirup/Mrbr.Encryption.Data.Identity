using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Mrbr.Encryption.Data.Common.Results;
using System.Security.Claims;

namespace Mrbr.Encryption.Data.Identity;

/// <summary>An Identity user store that safely mutates and queries protected claim records.</summary>
public class EncryptedIdentityClaimsUserStore<
    TUser, TRole, TContext, TUserClaim, TUserRole, TUserLogin, TUserToken, TRoleClaim, TUserPasskey> :
    UserStore<TUser, TRole, TContext, string, TUserClaim, TUserRole, TUserLogin, TUserToken, TRoleClaim, TUserPasskey>
    where TUser : IdentityUser
    where TRole : IdentityRole
    where TContext : DbContext
    where TUserClaim : EncryptedIdentityUserClaim<string>, new()
    where TUserRole : IdentityUserRole<string>, new()
    where TUserLogin : IdentityUserLogin<string>, new()
    where TUserToken : IdentityUserToken<string>, new()
    where TRoleClaim : EncryptedIdentityRoleClaim<string>, new()
    where TUserPasskey : IdentityUserPasskey<string>, new()
{
    private readonly IEncryptedIdentityUserLookup<TUser> _userLookup;
    private readonly IEncryptedIdentityClaimLookup<TUserClaim, TRoleClaim> _claimLookup;

    /// <summary>Initializes the protected claim-aware user store.</summary>
    public EncryptedIdentityClaimsUserStore(
        TContext context,
        IdentityErrorDescriber describer,
        IEncryptedIdentityUserLookup<TUser> userLookup,
        IEncryptedIdentityClaimLookup<TUserClaim, TRoleClaim> claimLookup)
        : base(context, describer)
    {
        _userLookup = userLookup ?? throw new ArgumentNullException(nameof(userLookup));
        _claimLookup = claimLookup ?? throw new ArgumentNullException(nameof(claimLookup));
    }

    /// <inheritdoc />
    public override async Task<TUser?> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken = default) =>
        GetSingle(await _userLookup.FindByNormalizedUserNameMatchesAsync(normalizedUserName, cancellationToken).ConfigureAwait(false), "user-name lookup");

    /// <inheritdoc />
    public override async Task<TUser?> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken = default) =>
        GetSingle(await _userLookup.FindByNormalizedEmailMatchesAsync(normalizedEmail, cancellationToken).ConfigureAwait(false), "email lookup");

    /// <inheritdoc />
    public override async Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(claims);
        foreach (Claim claim in claims)
        {
            TUserClaim entity = CreateUserClaim(user, claim);
            entity.RoutingHash = ComputeRoute(user.Id, claim, "add user claim");
            Context.Set<TUserClaim>().Add(entity);
        }
        await SaveChanges(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public override async Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken = default)
    {
        IReadOnlyList<TUserClaim> matches = await FindVerifiedAsync(user.Id, claim, cancellationToken).ConfigureAwait(false);
        foreach (TUserClaim entity in matches)
        {
            entity.ClaimType = newClaim.Type;
            entity.ClaimValue = newClaim.Value;
            entity.RoutingHash = ComputeRoute(user.Id, newClaim, "replace user claim");
        }
        await SaveChanges(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public override async Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default)
    {
        foreach (Claim claim in claims)
        {
            IReadOnlyList<TUserClaim> matches = await FindVerifiedAsync(user.Id, claim, cancellationToken).ConfigureAwait(false);
            Context.Set<TUserClaim>().RemoveRange(matches);
        }
        await SaveChanges(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public override async Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(claim);
        // Owner ID participates in the route, so this global operation intentionally scans and verifies
        // decrypted claims. Applications needing this operation at scale should add a separate audited route.
        List<TUserClaim> claims = await Context.Set<TUserClaim>().ToListAsync(cancellationToken).ConfigureAwait(false);
        string[] userIds = claims
            .Where(value => string.Equals(value.ClaimType, claim.Type, StringComparison.Ordinal) &&
                            string.Equals(value.ClaimValue, claim.Value, StringComparison.Ordinal))
            .Select(value => value.UserId)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        return await Context.Set<TUser>().Where(value => userIds.Contains(value.Id)).ToListAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task<IReadOnlyList<TUserClaim>> FindVerifiedAsync(string userId, Claim claim, CancellationToken cancellationToken)
    {
        string hash = ComputeRoute(userId, claim, "find user claim");
        IReadOnlyList<TUserClaim> candidates = await _claimLookup.FindUserCandidatesAsync(hash, cancellationToken).ConfigureAwait(false);
        if (candidates.Any(value => !string.Equals(value.UserId, userId, StringComparison.Ordinal) ||
                                    !string.Equals(value.ClaimType, claim.Type, StringComparison.Ordinal) ||
                                    !string.Equals(value.ClaimValue, claim.Value, StringComparison.Ordinal)))
        {
            throw new IdentityDataProtectionException(ProtectionFailureCode.HashMismatch, "find user claim");
        }
        return candidates;
    }

    private string ComputeRoute(string userId, Claim claim, string operation)
    {
        ProtectionResult<string> result = _claimLookup.ComputeUserRoutingHash(userId, claim.Type, claim.Value);
        return result.TryGetValue(out string? value)
            ? value
            : throw new IdentityDataProtectionException(result.FailureCode, operation);
    }

    private static T? GetSingle<T>(IReadOnlyList<T> matches, string operation) where T : class => matches.Count switch
    {
        0 => null,
        1 => matches[0],
        _ => throw new IdentityDataProtectionException(ProtectionFailureCode.AmbiguousMatch, operation)
    };
}
