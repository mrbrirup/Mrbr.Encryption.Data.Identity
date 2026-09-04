using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Mrbr.Encryption.Data.Common.Results;

namespace Mrbr.Encryption.Data.Identity;

/// <summary>A full-shape Identity user store with protected username and email lookup.</summary>
public class EncryptedIdentityFullUserStore<
    TUser, TRole, TContext, TUserClaim, TUserRole, TUserLogin, TUserToken, TRoleClaim, TUserPasskey> :
    UserStore<TUser, TRole, TContext, string, TUserClaim, TUserRole, TUserLogin, TUserToken, TRoleClaim, TUserPasskey>
    where TUser : IdentityUser
    where TRole : IdentityRole
    where TContext : DbContext
    where TUserClaim : IdentityUserClaim<string>, new()
    where TUserRole : IdentityUserRole<string>, new()
    where TUserLogin : IdentityUserLogin<string>, new()
    where TUserToken : IdentityUserToken<string>, new()
    where TRoleClaim : IdentityRoleClaim<string>, new()
    where TUserPasskey : IdentityUserPasskey<string>, new()
{
    private readonly IEncryptedIdentityUserLookup<TUser> _lookup;

    /// <summary>Initializes the full-shape protected user store.</summary>
    public EncryptedIdentityFullUserStore(TContext context, IdentityErrorDescriber describer, IEncryptedIdentityUserLookup<TUser> lookup)
        : base(context, describer) => _lookup = lookup ?? throw new ArgumentNullException(nameof(lookup));

    /// <inheritdoc />
    public override async Task<TUser?> FindByNameAsync(string value, CancellationToken cancellationToken = default) =>
        Single(await _lookup.FindByNormalizedUserNameMatchesAsync(value, cancellationToken).ConfigureAwait(false), "user-name lookup");

    /// <inheritdoc />
    public override async Task<TUser?> FindByEmailAsync(string value, CancellationToken cancellationToken = default) =>
        Single(await _lookup.FindByNormalizedEmailMatchesAsync(value, cancellationToken).ConfigureAwait(false), "email lookup");

    private static T? Single<T>(IReadOnlyList<T> values, string operation) where T : class => values.Count switch
    {
        0 => null,
        1 => values[0],
        _ => throw new IdentityDataProtectionException(ProtectionFailureCode.AmbiguousMatch, operation)
    };
}
