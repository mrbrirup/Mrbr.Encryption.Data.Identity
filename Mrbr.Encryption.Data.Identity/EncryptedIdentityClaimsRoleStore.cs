using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Mrbr.Encryption.Data.Common.Results;
using System.Security.Claims;

namespace Mrbr.Encryption.Data.Identity;

/// <summary>An encrypted role store that safely mutates protected role claims.</summary>
public class EncryptedIdentityClaimsRoleStore<TRole, TContext, TUserRole, TUserClaim, TRoleClaim> :
    RoleStore<TRole, TContext, string, TUserRole, TRoleClaim>
    where TRole : IdentityRole
    where TContext : DbContext
    where TUserRole : IdentityUserRole<string>, new()
    where TUserClaim : EncryptedIdentityUserClaim<string>, new()
    where TRoleClaim : EncryptedIdentityRoleClaim<string>, new()
{
    private readonly IEncryptedIdentityRoleLookup<TRole> _roleLookup;
    private readonly IEncryptedIdentityClaimLookup<TUserClaim, TRoleClaim> _claimLookup;

    /// <summary>Initializes the protected claim-aware role store.</summary>
    public EncryptedIdentityClaimsRoleStore(
        TContext context,
        IdentityErrorDescriber describer,
        IEncryptedIdentityRoleLookup<TRole> roleLookup,
        IEncryptedIdentityClaimLookup<TUserClaim, TRoleClaim> claimLookup)
        : base(context, describer)
    {
        _roleLookup = roleLookup ?? throw new ArgumentNullException(nameof(roleLookup));
        _claimLookup = claimLookup ?? throw new ArgumentNullException(nameof(claimLookup));
    }

    /// <inheritdoc />
    public override async Task<TRole?> FindByNameAsync(string normalizedName, CancellationToken cancellationToken = default)
    {
        IReadOnlyList<TRole> matches = await _roleLookup.FindByNormalizedNameMatchesAsync(normalizedName, cancellationToken).ConfigureAwait(false);
        return matches.Count switch
        {
            0 => null,
            1 => matches[0],
            _ => throw new IdentityDataProtectionException(ProtectionFailureCode.AmbiguousMatch, "role-name lookup")
        };
    }

    /// <inheritdoc />
    public override async Task AddClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(role);
        ArgumentNullException.ThrowIfNull(claim);
        TRoleClaim entity = CreateRoleClaim(role, claim);
        entity.RoutingHash = ComputeRoute(role.Id, claim, "add role claim");
        Context.Set<TRoleClaim>().Add(entity);
        await SaveChanges(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public override async Task RemoveClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(role);
        ArgumentNullException.ThrowIfNull(claim);
        string hash = ComputeRoute(role.Id, claim, "remove role claim");
        IReadOnlyList<TRoleClaim> candidates = await _claimLookup.FindRoleCandidatesAsync(hash, cancellationToken).ConfigureAwait(false);
        if (candidates.Any(value => !string.Equals(value.RoleId, role.Id, StringComparison.Ordinal) ||
                                    !string.Equals(value.ClaimType, claim.Type, StringComparison.Ordinal) ||
                                    !string.Equals(value.ClaimValue, claim.Value, StringComparison.Ordinal)))
        {
            throw new IdentityDataProtectionException(ProtectionFailureCode.HashMismatch, "remove role claim");
        }
        Context.Set<TRoleClaim>().RemoveRange(candidates);
        await SaveChanges(cancellationToken).ConfigureAwait(false);
    }

    private string ComputeRoute(string roleId, Claim claim, string operation)
    {
        ProtectionResult<string> result = _claimLookup.ComputeRoleRoutingHash(roleId, claim.Type, claim.Value);
        return result.TryGetValue(out string? value)
            ? value
            : throw new IdentityDataProtectionException(result.FailureCode, operation);
    }
}
