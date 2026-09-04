using Mrbr.Encryption.Data.Common.Results;

namespace Mrbr.Encryption.Data.Identity;

/// <summary>Computes and queries protected Identity token routes.</summary>
public interface IEncryptedIdentityTokenLookup<TToken> : IEncryptedIdentityTokenLookup<string, TToken>
{
}

/// <summary>Computes and queries protected Identity token routes for a selected key type.</summary>
public interface IEncryptedIdentityTokenLookup<TKey, TToken>
    where TKey : IEquatable<TKey>
{
    /// <summary>Computes the composite HMAC for a logical token route.</summary>
    ProtectionResult<string> ComputeRoutingHash(
        TKey userId,
        string loginProvider,
        string name);

    /// <summary>Returns database candidates for a routing HMAC.</summary>
    Task<IReadOnlyList<TToken>> FindCandidatesAsync(
        string routingHash,
        CancellationToken cancellationToken = default);
}
