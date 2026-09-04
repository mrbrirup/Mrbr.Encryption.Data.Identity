using Mrbr.Encryption.Data.Common.Results;

namespace Mrbr.Encryption.Data.Identity;

/// <summary>Computes and queries protected Identity claim routes.</summary>
public interface IEncryptedIdentityClaimLookup<TUserClaim, TRoleClaim>
{
    /// <summary>Computes the composite HMAC for a user claim.</summary>
    ProtectionResult<string> ComputeUserRoutingHash(string userId, string claimType, string claimValue);

    /// <summary>Computes the composite HMAC for a role claim.</summary>
    ProtectionResult<string> ComputeRoleRoutingHash(string roleId, string claimType, string claimValue);

    /// <summary>Returns user-claim candidates for a routing HMAC.</summary>
    Task<IReadOnlyList<TUserClaim>> FindUserCandidatesAsync(string routingHash, CancellationToken cancellationToken = default);

    /// <summary>Returns role-claim candidates for a routing HMAC.</summary>
    Task<IReadOnlyList<TRoleClaim>> FindRoleCandidatesAsync(string routingHash, CancellationToken cancellationToken = default);
}
