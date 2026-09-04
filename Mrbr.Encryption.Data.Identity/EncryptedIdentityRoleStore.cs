using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Mrbr.Encryption.Data.Identity;

/// <summary>A role store that routes normalized-name lookup through keyed-hash candidates.</summary>
public class EncryptedIdentityRoleStore<TRole, TContext, TUserRole, TRoleClaim> :
    RoleStore<TRole, TContext, string, TUserRole, TRoleClaim>
    where TRole : IdentityRole
    where TContext : DbContext
    where TUserRole : IdentityUserRole<string>, new()
    where TRoleClaim : IdentityRoleClaim<string>, new()
{
    private readonly IEncryptedIdentityRoleLookup<TRole> _lookup;

    /// <summary>Initializes the protected role store.</summary>
    public EncryptedIdentityRoleStore(
        TContext context,
        IdentityErrorDescriber describer,
        IEncryptedIdentityRoleLookup<TRole> lookup)
        : base(context, describer)
    {
        _lookup = lookup ?? throw new ArgumentNullException(nameof(lookup));
    }

    /// <inheritdoc />
    public override async Task<TRole?> FindByNameAsync(
        string normalizedName,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(normalizedName);
        IReadOnlyList<TRole> matches = await _lookup
            .FindByNormalizedNameMatchesAsync(normalizedName, cancellationToken)
            .ConfigureAwait(false);

        return matches.Count switch
        {
            0 => null,
            1 => matches[0],
            _ => throw new InvalidOperationException(
                "Identity role lookup produced multiple verified plaintext matches.")
        };
    }
}
