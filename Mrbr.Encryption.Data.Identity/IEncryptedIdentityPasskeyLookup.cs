using Mrbr.Encryption.Data.Common.Results;

namespace Mrbr.Encryption.Data.Identity;

/// <summary>Computes and queries protected passkey credential routes.</summary>
public interface IEncryptedIdentityPasskeyLookup<TPasskey>
{
    /// <summary>Computes the keyed route for a credential identifier.</summary>
    ProtectionResult<string> ComputeRoutingHash(byte[] credentialId);
    /// <summary>Returns candidates for a credential route.</summary>
    Task<IReadOnlyList<TPasskey>> FindCandidatesAsync(string routingHash, CancellationToken cancellationToken = default);
}
