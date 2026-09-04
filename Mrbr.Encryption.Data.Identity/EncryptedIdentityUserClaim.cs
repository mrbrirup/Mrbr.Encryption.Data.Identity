using Microsoft.AspNetCore.Identity;
using Mrbr.Encryption.Data.Common.Attributes;

namespace Mrbr.Encryption.Data.Identity;

/// <summary>An Identity user claim with a composite keyed routing hash.</summary>
public class EncryptedIdentityUserClaim<TKey> : IdentityUserClaim<TKey>
    where TKey : IEquatable<TKey>
{
    /// <summary>Gets or sets the HMAC route over user ID, claim type, and claim value.</summary>
    public string RoutingHash { get; set; } = null!;
}

/// <summary>A reusable string-key Identity user claim with encrypted contents.</summary>
public class EncryptedIdentityUserClaim : EncryptedIdentityUserClaim<string>
{
    /// <inheritdoc />
    [Encrypted("IdentityAuthorization")]
    public override string? ClaimType { get; set; }

    /// <inheritdoc />
    [Encrypted("IdentityAuthorization")]
    public override string? ClaimValue { get; set; }
}
