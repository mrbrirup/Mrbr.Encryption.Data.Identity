using Mrbr.Encryption.Data.Common.Results;

namespace Mrbr.Encryption.Data.Identity;

/// <summary>String-key compatibility contract for protected Identity claim routes.</summary>
public interface IEncryptedIdentityClaimLookup<TUserClaim, TRoleClaim> :
    IEncryptedIdentityClaimLookup<string, TUserClaim, TRoleClaim>
{
}

/// <summary>Computes and queries protected Identity claim routes.</summary>
public interface IEncryptedIdentityClaimLookup<TKey, TUserClaim, TRoleClaim>
    where TKey : IEquatable<TKey>
{
    /// <summary>Computes the composite HMAC for a user claim.</summary>
    ProtectionResult<string> ComputeUserRoutingHash(TKey userId, string claimType, string claimValue);

    /// <summary>Computes the composite HMAC for a role claim.</summary>
    ProtectionResult<string> ComputeRoleRoutingHash(TKey roleId, string claimType, string claimValue);

    /// <summary>Returns user-claim candidates for a routing HMAC.</summary>
    Task<IReadOnlyList<TUserClaim>> FindUserCandidatesAsync(string routingHash, CancellationToken cancellationToken = default);

    /// <summary>Returns role-claim candidates for a routing HMAC.</summary>
    Task<IReadOnlyList<TRoleClaim>> FindRoleCandidatesAsync(string routingHash, CancellationToken cancellationToken = default);
}
