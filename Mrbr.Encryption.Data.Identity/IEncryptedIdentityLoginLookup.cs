using Mrbr.Encryption.Data.Common.Results;

namespace Mrbr.Encryption.Data.Identity;

/// <summary>Computes and queries protected external-login routes.</summary>
public interface IEncryptedIdentityLoginLookup<TLogin>
{
    /// <summary>Computes the composite HMAC for a provider and provider key.</summary>
    ProtectionResult<string> ComputeRoutingHash(string loginProvider, string providerKey);

    /// <summary>Returns database candidates for a routing HMAC.</summary>
    Task<IReadOnlyList<TLogin>> FindCandidatesAsync(string routingHash, CancellationToken cancellationToken = default);
}
