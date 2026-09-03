using Mrbr.Encryption.Data.Common.Results;

namespace Mrbr.Encryption.Data.Identity;

/// <summary>Computes and queries protected Identity token routes.</summary>
public interface IEncryptedIdentityTokenLookup<TToken>
{
    /// <summary>Computes the composite HMAC for a logical token route.</summary>
    ProtectionResult<string> ComputeRoutingHash(
        string userId,
        string loginProvider,
        string name);

    /// <summary>Returns database candidates for a routing HMAC.</summary>
    Task<IReadOnlyList<TToken>> FindCandidatesAsync(
        string routingHash,
        CancellationToken cancellationToken = default);
}
