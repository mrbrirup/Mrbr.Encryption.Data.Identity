using Microsoft.AspNetCore.Identity;
using Mrbr.Encryption.Data.Common.Attributes;

namespace Mrbr.Encryption.Data.Identity;

/// <summary>An Identity role claim with a composite keyed routing hash.</summary>
public class EncryptedIdentityRoleClaim<TKey> : IdentityRoleClaim<TKey>
    where TKey : IEquatable<TKey>
{
    /// <summary>Gets or sets the HMAC route over role ID, claim type, and claim value.</summary>
    public string RoutingHash { get; set; } = null!;

    /// <inheritdoc />
    [Encrypted("IdentityAuthorization")]
    public override string? ClaimType { get; set; }

    /// <inheritdoc />
    [Encrypted("IdentityAuthorization")]
    public override string? ClaimValue { get; set; }
}

/// <summary>A reusable string-key Identity role claim with encrypted contents.</summary>
public class EncryptedIdentityRoleClaim : EncryptedIdentityRoleClaim<string>
{
}
