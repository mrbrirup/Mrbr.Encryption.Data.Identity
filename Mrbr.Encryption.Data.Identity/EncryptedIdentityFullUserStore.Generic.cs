using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Mrbr.Encryption.Data.Common.Results;
using System.Security.Claims;

namespace Mrbr.Encryption.Data.Identity;

/// <summary>A full-shape protected Identity store with an application-selected relational key type.</summary>
public class EncryptedIdentityFullUserStore<
    TKey, TUser, TRole, TContext, TUserClaim, TUserRole, TUserLogin, TUserToken, TRoleClaim, TUserPasskey> :
    UserStore<TUser, TRole, TContext, TKey, TUserClaim, TUserRole, TUserLogin, TUserToken, TRoleClaim, TUserPasskey>
    where TKey : IEquatable<TKey>
    where TUser : IdentityUser<TKey>
    where TRole : IdentityRole<TKey>
    where TContext : DbContext
    where TUserClaim : EncryptedIdentityUserClaim<TKey>, new()
    where TUserRole : IdentityUserRole<TKey>, new()
    where TUserLogin : IdentityUserLogin<TKey>, new()
    where TUserToken : EncryptedIdentityUserToken<TKey>, new()
    where TRoleClaim : EncryptedIdentityRoleClaim<TKey>, new()
    where TUserPasskey : IdentityUserPasskey<TKey>, new()
{
    private readonly IEncryptedIdentityUserLookup<TKey, TUser> _lookup;
    private readonly IEncryptedIdentityTokenLookup<TKey, TUserToken>? _tokenLookup;
    private readonly IEncryptedIdentityClaimLookup<TKey, TUserClaim, TRoleClaim>? _claimLookup;

    /// <summary>Initializes the generic full-shape protected user store.</summary>
    public EncryptedIdentityFullUserStore(
        TContext context,
        IdentityErrorDescriber describer,
        IEncryptedIdentityUserLookup<TKey, TUser> lookup)
        : base(context, describer) => _lookup = lookup ?? throw new ArgumentNullException(nameof(lookup));

    /// <summary>Initializes the generic store with protected token routing.</summary>
    public EncryptedIdentityFullUserStore(TContext context, IdentityErrorDescriber describer,
        IEncryptedIdentityUserLookup<TKey, TUser> lookup, IEncryptedIdentityTokenLookup<TKey, TUserToken> tokenLookup)
        : this(context, describer, lookup) => _tokenLookup = tokenLookup ?? throw new ArgumentNullException(nameof(tokenLookup));

    /// <summary>Initializes the generic store with protected claim routing.</summary>
    public EncryptedIdentityFullUserStore(TContext context, IdentityErrorDescriber describer,
        IEncryptedIdentityUserLookup<TKey, TUser> lookup, IEncryptedIdentityClaimLookup<TKey, TUserClaim, TRoleClaim> claimLookup)
        : this(context, describer, lookup) => _claimLookup = claimLookup ?? throw new ArgumentNullException(nameof(claimLookup));

    /// <summary>Initializes the generic store with protected token and claim routing.</summary>
    public EncryptedIdentityFullUserStore(TContext context, IdentityErrorDescriber describer,
        IEncryptedIdentityUserLookup<TKey, TUser> lookup, IEncryptedIdentityTokenLookup<TKey, TUserToken> tokenLookup,
        IEncryptedIdentityClaimLookup<TKey, TUserClaim, TRoleClaim> claimLookup)
        : this(context, describer, lookup)
    {
        _tokenLookup = tokenLookup ?? throw new ArgumentNullException(nameof(tokenLookup));
        _claimLookup = claimLookup ?? throw new ArgumentNullException(nameof(claimLookup));
    }

    /// <inheritdoc />
    public override async Task<TUser?> FindByNameAsync(string value, CancellationToken cancellationToken = default) =>
        Single(await _lookup.FindByNormalizedUserNameMatchesAsync(value, cancellationToken).ConfigureAwait(false), "user-name lookup");

    /// <inheritdoc />
    public override async Task<TUser?> FindByEmailAsync(string value, CancellationToken cancellationToken = default) =>
        Single(await _lookup.FindByNormalizedEmailMatchesAsync(value, cancellationToken).ConfigureAwait(false), "email lookup");

    /// <inheritdoc />
    public override async Task SetTokenAsync(TUser user, string loginProvider, string name, string? value, CancellationToken cancellationToken)
    {
        TUserToken? token = await FindTokenAsync(user, loginProvider, name, cancellationToken).ConfigureAwait(false);
        if (token is null)
        {
            token = CreateUserToken(user, loginProvider, name, value);
            await AddUserTokenAsync(token).ConfigureAwait(false);
        }
        else token.Value = value;
        await SaveChanges(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    protected override async Task<TUserToken?> FindTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken)
    {
        IEncryptedIdentityTokenLookup<TKey, TUserToken> lookup = _tokenLookup ?? throw Missing("token");
        string route = Require(lookup.ComputeRoutingHash(user.Id, loginProvider, name), "find token");
        IReadOnlyList<TUserToken> candidates = await lookup.FindCandidatesAsync(route, cancellationToken).ConfigureAwait(false);
        foreach (TUserToken candidate in candidates)
        {
            if (!EqualityComparer<TKey>.Default.Equals(candidate.UserId, user.Id) ||
                !StringComparer.Ordinal.Equals(candidate.LoginProvider, loginProvider) || !StringComparer.Ordinal.Equals(candidate.Name, name))
                throw new IdentityDataProtectionException(ProtectionFailureCode.HashMismatch, "find token");
        }
        return candidates.Count switch { 0 => null, 1 => candidates[0], _ => throw new IdentityDataProtectionException(ProtectionFailureCode.AmbiguousMatch, "find token") };
    }

    /// <inheritdoc />
    protected override Task AddUserTokenAsync(TUserToken token)
    {
        IEncryptedIdentityTokenLookup<TKey, TUserToken> lookup = _tokenLookup ?? throw Missing("token");
        if (token.TokenId == Guid.Empty) token.TokenId = Guid.CreateVersion7();
        token.RoutingHash = Require(lookup.ComputeRoutingHash(token.UserId, token.LoginProvider, token.Name), "add token");
        Context.Set<TUserToken>().Add(token);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    protected override Task RemoveUserTokenAsync(TUserToken token)
    {
        Context.Set<TUserToken>().Remove(token);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public override async Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default)
    {
        foreach (Claim claim in claims)
        {
            TUserClaim entity = CreateUserClaim(user, claim);
            entity.RoutingHash = ClaimRoute(user.Id, claim, "add user claim");
            Context.Set<TUserClaim>().Add(entity);
        }
        await SaveChanges(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public override async Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken = default)
    {
        foreach (TUserClaim entity in await FindClaimsAsync(user.Id, claim, cancellationToken).ConfigureAwait(false))
        {
            entity.ClaimType = newClaim.Type; entity.ClaimValue = newClaim.Value;
            entity.RoutingHash = ClaimRoute(user.Id, newClaim, "replace user claim");
        }
        await SaveChanges(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public override async Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default)
    {
        foreach (Claim claim in claims) Context.Set<TUserClaim>().RemoveRange(await FindClaimsAsync(user.Id, claim, cancellationToken).ConfigureAwait(false));
        await SaveChanges(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public override async Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken = default)
    {
        List<TKey> ids = (await Context.Set<TUserClaim>().ToListAsync(cancellationToken).ConfigureAwait(false))
            .Where(value => StringComparer.Ordinal.Equals(value.ClaimType, claim.Type) && StringComparer.Ordinal.Equals(value.ClaimValue, claim.Value))
            .Select(value => value.UserId).Distinct().ToList();
        return await Context.Set<TUser>().Where(value => ids.Contains(value.Id)).ToListAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task<IReadOnlyList<TUserClaim>> FindClaimsAsync(TKey userId, Claim claim, CancellationToken cancellationToken)
    {
        IEncryptedIdentityClaimLookup<TKey, TUserClaim, TRoleClaim> lookup = _claimLookup ?? throw Missing("claim");
        IReadOnlyList<TUserClaim> values = await lookup.FindUserCandidatesAsync(ClaimRoute(userId, claim, "find user claim"), cancellationToken).ConfigureAwait(false);
        if (values.Any(value => !EqualityComparer<TKey>.Default.Equals(value.UserId, userId) || !StringComparer.Ordinal.Equals(value.ClaimType, claim.Type) || !StringComparer.Ordinal.Equals(value.ClaimValue, claim.Value)))
            throw new IdentityDataProtectionException(ProtectionFailureCode.HashMismatch, "find user claim");
        return values;
    }

    private string ClaimRoute(TKey userId, Claim claim, string operation) =>
        Require((_claimLookup ?? throw Missing("claim")).ComputeUserRoutingHash(userId, claim.Type, claim.Value), operation);

    private static string Require(ProtectionResult<string> result, string operation) => result.TryGetValue(out string? value)
        ? value : throw new IdentityDataProtectionException(result.FailureCode, operation);

    private static InvalidOperationException Missing(string feature) => new($"The protected {feature} lookup was not configured for this store.");

    private static T? Single<T>(IReadOnlyList<T> values, string operation) where T : class => values.Count switch
    {
        0 => null,
        1 => values[0],
        _ => throw new IdentityDataProtectionException(ProtectionFailureCode.AmbiguousMatch, operation)
    };
}
