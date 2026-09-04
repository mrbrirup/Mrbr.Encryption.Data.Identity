using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Mrbr.Encryption.Data.Common.Results;

namespace Mrbr.Encryption.Data.Identity;

/// <summary>A protected Identity user store with an application-selected relational key type.</summary>
public class EncryptedIdentityUserStore<TKey, TUser, TRole, TContext> :
    UserStore<TUser, TRole, TContext, TKey>
    where TKey : IEquatable<TKey>
    where TUser : IdentityUser<TKey>
    where TRole : IdentityRole<TKey>
    where TContext : DbContext
{
    private readonly IEncryptedIdentityUserLookup<TKey, TUser> _lookup;

    /// <summary>Initializes the generic protected user store.</summary>
    public EncryptedIdentityUserStore(TContext context, IdentityErrorDescriber describer, IEncryptedIdentityUserLookup<TKey, TUser> lookup)
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
