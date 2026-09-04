using Microsoft.AspNetCore.Identity;
using Mrbr.Encryption.Data.Common.Algorithms;
using Mrbr.Encryption.Data.Common.Attributes;

namespace Mrbr.Encryption.Data.Identity;

/// <summary>
/// A reusable string-key Identity user whose confidential string fields are protected at rest.
/// </summary>
/// <remarks>
/// Normalized username and email values use separately named keyed-HMAC routes. The default email
/// route is non-unique; applications requiring unique email should derive from this type, override
/// <see cref="NormalizedEmail"/>, and apply a unique <see cref="HashedAttribute"/> configuration.
/// Relational identifiers and concurrency state remain plaintext. Operational flags, timestamps,
/// and counters are independently protected through the <c>IdentityOperational</c> domain.
/// </remarks>
public class EncryptedIdentityUser : IdentityUser {
    /// <inheritdoc />
    [Encrypted("IdentityPII")]
    public override string? UserName { get; set; }

    /// <inheritdoc />
    [Encrypted("IdentityPII")]
    [Hashed("IdentityLookup", "IdentityUserName", HashIndexType.Unique, DataNormalization.None)]
    public override string? NormalizedUserName { get; set; }

    /// <inheritdoc />
    [Encrypted("IdentityPII")]
    public override string? Email { get; set; }

    /// <inheritdoc />
    [Encrypted("IdentityPII")]
    [Hashed("IdentityLookup", "IdentityEmail", HashIndexType.NonUnique, DataNormalization.None)]
    public override string? NormalizedEmail { get; set; }

    /// <inheritdoc />
    [Encrypted("IdentityPII")]
    public override string? PhoneNumber { get; set; }

    /// <inheritdoc />
    public override string? PasswordHash { get; set; }

    /// <inheritdoc />
    [Encrypted("IdentityCredential")]
    public override string? SecurityStamp { get; set; }

    /// <inheritdoc />
    [Encrypted("IdentityOperational")]
    public override bool EmailConfirmed { get; set; }

    /// <inheritdoc />
    [Encrypted("IdentityOperational")]
    public override bool PhoneNumberConfirmed { get; set; }

    /// <inheritdoc />
    [Encrypted("IdentityOperational")]
    public override bool TwoFactorEnabled { get; set; }

    /// <inheritdoc />
    [Encrypted("IdentityOperational")]
    public override DateTimeOffset? LockoutEnd { get; set; }

    /// <inheritdoc />
    [Encrypted("IdentityOperational")]
    public override bool LockoutEnabled { get; set; }

    /// <inheritdoc />
    [Encrypted("IdentityOperational")]
    public override int AccessFailedCount { get; set; }
}
