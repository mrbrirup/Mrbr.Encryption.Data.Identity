using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Mrbr.Encryption.Data.Common.Results;
using System.Security.Claims;

namespace Mrbr.Encryption.Data.Identity;

/// <summary>Combines protected token persistence with protected claim mutation and lookup.</summary>
public class EncryptedIdentityTokenClaimsUserStore<
    TUser, TRole, TContext, TUserClaim, TUserRole, TUserLogin, TUserToken, TRoleClaim, TUserPasskey> :
    EncryptedIdentityTokenUserStore<TUser, TRole, TContext, TUserClaim, TUserRole, TUserLogin, TUserToken, TRoleClaim, TUserPasskey>
    where TUser : IdentityUser
    where TRole : IdentityRole
    where TContext : DbContext
    where TUserClaim : EncryptedIdentityUserClaim<string>, new()
    where TUserRole : IdentityUserRole<string>, new()
    where TUserLogin : IdentityUserLogin<string>, new()
    where TUserToken : EncryptedIdentityUserToken<string>, new()
    where TRoleClaim : EncryptedIdentityRoleClaim<string>, new()
    where TUserPasskey : IdentityUserPasskey<string>, new()
{
    private readonly IEncryptedIdentityClaimLookup<TUserClaim, TRoleClaim> _claimLookup;

    /// <summary>Initializes the combined protected store.</summary>
    public EncryptedIdentityTokenClaimsUserStore(
        TContext context,
        IdentityErrorDescriber describer,
        IEncryptedIdentityUserLookup<TUser> userLookup,
        IEncryptedIdentityTokenLookup<TUserToken> tokenLookup,
        IEncryptedIdentityClaimLookup<TUserClaim, TRoleClaim> claimLookup)
        : base(context, describer, userLookup, tokenLookup) =>
        _claimLookup = claimLookup ?? throw new ArgumentNullException(nameof(claimLookup));

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
            Context.Set<TUserClaim>().RemoveRange(await FindVerifiedAsync(user.Id, claim, cancellationToken).ConfigureAwait(false));
        }
        await SaveChanges(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public override async Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken = default)
    {
        List<TUserClaim> claims = await Context.Set<TUserClaim>().ToListAsync(cancellationToken).ConfigureAwait(false);
        string[] ids = claims.Where(value => string.Equals(value.ClaimType, claim.Type, StringComparison.Ordinal) &&
                                             string.Equals(value.ClaimValue, claim.Value, StringComparison.Ordinal))
            .Select(value => value.UserId).Distinct(StringComparer.Ordinal).ToArray();
        return await Context.Set<TUser>().Where(value => ids.Contains(value.Id)).ToListAsync(cancellationToken).ConfigureAwait(false);
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
}
