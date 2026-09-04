using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Mrbr.Encryption.Data.Common.Results;
using System.Security.Claims;

namespace Mrbr.Encryption.Data.Identity;

/// <summary>A protected Identity role store with an application-selected relational key type.</summary>
public class EncryptedIdentityRoleStore<TKey, TRole, TContext, TUserRole, TUserClaim, TRoleClaim> :
    RoleStore<TRole, TContext, TKey, TUserRole, TRoleClaim>
    where TKey : IEquatable<TKey>
    where TRole : IdentityRole<TKey>
    where TContext : DbContext
    where TUserRole : IdentityUserRole<TKey>, new()
    where TUserClaim : EncryptedIdentityUserClaim<TKey>, new()
    where TRoleClaim : EncryptedIdentityRoleClaim<TKey>, new()
{
    private readonly IEncryptedIdentityRoleLookup<TKey, TRole> _lookup;
    private readonly IEncryptedIdentityClaimLookup<TKey, TUserClaim, TRoleClaim>? _claimLookup;

    /// <summary>Initializes the generic protected role store.</summary>
    public EncryptedIdentityRoleStore(TContext context, IdentityErrorDescriber describer, IEncryptedIdentityRoleLookup<TKey, TRole> lookup)
        : base(context, describer) => _lookup = lookup ?? throw new ArgumentNullException(nameof(lookup));

    /// <summary>Initializes the generic protected role store with claim routing.</summary>
    public EncryptedIdentityRoleStore(TContext context, IdentityErrorDescriber describer,
        IEncryptedIdentityRoleLookup<TKey, TRole> lookup,
        IEncryptedIdentityClaimLookup<TKey, TUserClaim, TRoleClaim> claimLookup)
        : this(context, describer, lookup) => _claimLookup = claimLookup ?? throw new ArgumentNullException(nameof(claimLookup));

    /// <inheritdoc />
    public override async Task<TRole?> FindByNameAsync(string value, CancellationToken cancellationToken = default)
    {
        IReadOnlyList<TRole> values = await _lookup.FindByNormalizedNameMatchesAsync(value, cancellationToken).ConfigureAwait(false);
        return values.Count switch
        {
            0 => null,
            1 => values[0],
            _ => throw new IdentityDataProtectionException(ProtectionFailureCode.AmbiguousMatch, "role-name lookup")
        };
    }

    /// <inheritdoc />
    public override async Task AddClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = default)
    {
        IEncryptedIdentityClaimLookup<TKey, TUserClaim, TRoleClaim> lookup = _claimLookup ?? throw Missing();
        TRoleClaim entity = CreateRoleClaim(role, claim);
        entity.RoutingHash = Require(lookup.ComputeRoleRoutingHash(role.Id, claim.Type, claim.Value), "add role claim");
        Context.Set<TRoleClaim>().Add(entity);
        await SaveChanges(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public override async Task RemoveClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = default)
    {
        IEncryptedIdentityClaimLookup<TKey, TUserClaim, TRoleClaim> lookup = _claimLookup ?? throw Missing();
        string route = Require(lookup.ComputeRoleRoutingHash(role.Id, claim.Type, claim.Value), "remove role claim");
        IReadOnlyList<TRoleClaim> candidates = await lookup.FindRoleCandidatesAsync(route, cancellationToken).ConfigureAwait(false);
        if (candidates.Any(value => !EqualityComparer<TKey>.Default.Equals(value.RoleId, role.Id) ||
            !StringComparer.Ordinal.Equals(value.ClaimType, claim.Type) || !StringComparer.Ordinal.Equals(value.ClaimValue, claim.Value)))
            throw new IdentityDataProtectionException(ProtectionFailureCode.HashMismatch, "remove role claim");
        Context.Set<TRoleClaim>().RemoveRange(candidates);
        await SaveChanges(cancellationToken).ConfigureAwait(false);
    }

    private static string Require(ProtectionResult<string> result, string operation) => result.TryGetValue(out string? value)
        ? value : throw new IdentityDataProtectionException(result.FailureCode, operation);

    private static InvalidOperationException Missing() => new("The protected claim lookup was not configured for this role store.");
}
