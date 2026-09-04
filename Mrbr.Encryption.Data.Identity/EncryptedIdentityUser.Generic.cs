using Microsoft.AspNetCore.Identity;
using Mrbr.Encryption.Data.Common.Algorithms;
using Mrbr.Encryption.Data.Common.Attributes;
#pragma warning disable CS1591

namespace Mrbr.Encryption.Data.Identity;

/// <summary>A provider-neutral protected Identity user with an application-selected key type.</summary>
public class EncryptedIdentityUser<TKey> : IdentityUser<TKey> where TKey : IEquatable<TKey>
{
    [Encrypted("IdentityPII")] public override string? UserName { get; set; }
    [Encrypted("IdentityPII"), Hashed("IdentityLookup", "IdentityUserName", HashIndexType.Unique, DataNormalization.None)] public override string? NormalizedUserName { get; set; }
    [Encrypted("IdentityPII")] public override string? Email { get; set; }
    [Encrypted("IdentityPII"), Hashed("IdentityLookup", "IdentityEmail", HashIndexType.NonUnique, DataNormalization.None)] public override string? NormalizedEmail { get; set; }
    [Encrypted("IdentityPII")] public override string? PhoneNumber { get; set; }
    [Encrypted("IdentityCredential")] public override string? SecurityStamp { get; set; }
    [Encrypted("IdentityOperational")] public override bool EmailConfirmed { get; set; }
    [Encrypted("IdentityOperational")] public override bool PhoneNumberConfirmed { get; set; }
    [Encrypted("IdentityOperational")] public override bool TwoFactorEnabled { get; set; }
    [Encrypted("IdentityOperational")] public override DateTimeOffset? LockoutEnd { get; set; }
    [Encrypted("IdentityOperational")] public override bool LockoutEnabled { get; set; }
    [Encrypted("IdentityOperational")] public override int AccessFailedCount { get; set; }
}
#pragma warning restore CS1591
