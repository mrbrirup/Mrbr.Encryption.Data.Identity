using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Mrbr.Encryption.Data.Common.Results;
using System.Security.Cryptography;

namespace Mrbr.Encryption.Data.Identity;

/// <summary>An Identity store that adds protected UUIDv7 user-token persistence to encrypted user lookup.</summary>
public class EncryptedIdentityTokenUserStore<
    TUser,
    TRole,
    TContext,
    TUserClaim,
    TUserRole,
    TUserLogin,
    TUserToken,
    TRoleClaim,
    TUserPasskey> : UserStore<
        TUser,
        TRole,
        TContext,
        string,
        TUserClaim,
        TUserRole,
        TUserLogin,
        TUserToken,
        TRoleClaim,
        TUserPasskey>
    where TUser : IdentityUser
    where TRole : IdentityRole
    where TContext : DbContext
    where TUserClaim : IdentityUserClaim<string>, new()
    where TUserRole : IdentityUserRole<string>, new()
    where TUserLogin : IdentityUserLogin<string>, new()
    where TUserToken : EncryptedIdentityUserToken<string>, new()
    where TRoleClaim : IdentityRoleClaim<string>, new()
    where TUserPasskey : IdentityUserPasskey<string>, new()
{
    private readonly IEncryptedIdentityUserLookup<TUser> _userLookup;
    private readonly IEncryptedIdentityTokenLookup<TUserToken> _tokenLookup;

    /// <summary>Initializes the protected Identity store.</summary>
    public EncryptedIdentityTokenUserStore(
        TContext context,
        IdentityErrorDescriber describer,
        IEncryptedIdentityUserLookup<TUser> userLookup,
        IEncryptedIdentityTokenLookup<TUserToken> tokenLookup)
        : base(context, describer)
    {
        _userLookup = userLookup ?? throw new ArgumentNullException(nameof(userLookup));
        _tokenLookup = tokenLookup ?? throw new ArgumentNullException(nameof(tokenLookup));
    }

    /// <inheritdoc />
    public override async Task<TUser?> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(normalizedUserName);
        IReadOnlyList<TUser> matches = await _userLookup
            .FindByNormalizedUserNameMatchesAsync(normalizedUserName, cancellationToken)
            .ConfigureAwait(false);
        return GetSingleMatch(matches, "user-name lookup");
    }

    /// <inheritdoc />
    public override async Task<TUser?> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(normalizedEmail);
        IReadOnlyList<TUser> matches = await _userLookup
            .FindByNormalizedEmailMatchesAsync(normalizedEmail, cancellationToken)
            .ConfigureAwait(false);
        return GetSingleMatch(matches, "email lookup");
    }

    /// <inheritdoc />
    public override async Task SetTokenAsync(
        TUser user,
        string loginProvider,
        string name,
        string? value,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(loginProvider);
        ArgumentNullException.ThrowIfNull(name);
        cancellationToken.ThrowIfCancellationRequested();

        TUserToken? token = await FindTokenAsync(user, loginProvider, name, cancellationToken).ConfigureAwait(false);
        bool added = token is null;
        if (added)
        {
            token = CreateUserToken(user, loginProvider, name, value);
            await AddUserTokenAsync(token).ConfigureAwait(false);
        }
        else
        {
            token!.Value = value;
        }

        try
        {
            await SaveChanges(cancellationToken).ConfigureAwait(false);
        }
        catch (DbUpdateException) when (added)
        {
            Context.Entry(token!).State = EntityState.Detached;
            TUserToken? concurrent = await FindTokenAsync(user, loginProvider, name, cancellationToken).ConfigureAwait(false);
            if (concurrent is null)
            {
                throw new IdentityDataProtectionException(ProtectionFailureCode.PersistenceConflict, "set token");
            }

            concurrent.Value = value;
            try
            {
                await SaveChanges(cancellationToken).ConfigureAwait(false);
            }
            catch (DbUpdateException)
            {
                throw new IdentityDataProtectionException(ProtectionFailureCode.PersistenceConflict, "set token");
            }
        }
        catch (DbUpdateException)
        {
            throw new IdentityDataProtectionException(ProtectionFailureCode.PersistenceConflict, "set token");
        }
    }

    /// <inheritdoc />
    protected override async Task<TUserToken?> FindTokenAsync(
        TUser user,
        string loginProvider,
        string name,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(loginProvider);
        ArgumentNullException.ThrowIfNull(name);

        string hash = GetRoutingHash(user.Id, loginProvider, name, "find token");
        IReadOnlyList<TUserToken> candidates;
        try
        {
            candidates = await _tokenLookup
                .FindCandidatesAsync(hash, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (KeyNotFoundException)
        {
            throw new IdentityDataProtectionException(ProtectionFailureCode.KeyNotFound, "find token");
        }
        catch (NotSupportedException)
        {
            throw new IdentityDataProtectionException(ProtectionFailureCode.UnsupportedAlgorithm, "find token");
        }
        catch (FormatException)
        {
            throw new IdentityDataProtectionException(ProtectionFailureCode.InvalidPayload, "find token");
        }
        catch (CryptographicException)
        {
            throw new IdentityDataProtectionException(ProtectionFailureCode.AuthenticationFailed, "find token");
        }

        TUserToken? verified = null;
        foreach (TUserToken candidate in candidates)
        {
            if (!string.Equals(candidate.UserId, user.Id, StringComparison.Ordinal) ||
                !string.Equals(candidate.LoginProvider, loginProvider, StringComparison.Ordinal) ||
                !string.Equals(candidate.Name, name, StringComparison.Ordinal))
            {
                throw new IdentityDataProtectionException(ProtectionFailureCode.HashMismatch, "find token");
            }

            if (verified is not null)
            {
                throw new IdentityDataProtectionException(ProtectionFailureCode.AmbiguousMatch, "find token");
            }

            verified = candidate;
        }

        return verified;
    }

    /// <inheritdoc />
    protected override Task AddUserTokenAsync(TUserToken token)
    {
        ArgumentNullException.ThrowIfNull(token);
        if (token.TokenId == Guid.Empty)
        {
            token.TokenId = Guid.CreateVersion7();
        }

        if (token.TokenId.Version != 7)
        {
            throw new ArgumentException("Protected Identity token identifiers must be UUIDv7 values.", nameof(token));
        }

        token.RoutingHash = GetRoutingHash(token.UserId, token.LoginProvider, token.Name, "add token");
        Context.Set<TUserToken>().Add(token);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    protected override Task RemoveUserTokenAsync(TUserToken token)
    {
        ArgumentNullException.ThrowIfNull(token);
        Context.Set<TUserToken>().Remove(token);
        return Task.CompletedTask;
    }

    private string GetRoutingHash(string userId, string loginProvider, string name, string operation)
    {
        ProtectionResult<string> result = _tokenLookup.ComputeRoutingHash(userId, loginProvider, name);
        if (!result.TryGetValue(out string? hash))
        {
            throw new IdentityDataProtectionException(result.FailureCode, operation);
        }

        return hash;
    }

    private static T? GetSingleMatch<T>(IReadOnlyList<T> matches, string operation)
        where T : class
    {
        ArgumentNullException.ThrowIfNull(matches);
        return matches.Count switch
        {
            0 => null,
            1 => matches[0],
            _ => throw new IdentityDataProtectionException(ProtectionFailureCode.AmbiguousMatch, operation)
        };
    }
}
