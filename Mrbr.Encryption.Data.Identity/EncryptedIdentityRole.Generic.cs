using Microsoft.AspNetCore.Identity;
using Mrbr.Encryption.Data.Common.Algorithms;
using Mrbr.Encryption.Data.Common.Attributes;
#pragma warning disable CS1591

namespace Mrbr.Encryption.Data.Identity;

/// <summary>A protected Identity role with an application-selected key type.</summary>
public class EncryptedIdentityRole<TKey> : IdentityRole<TKey> where TKey : IEquatable<TKey>
{
    [Encrypted("IdentityAuthorization")] public override string? Name { get; set; }
    [Encrypted("IdentityAuthorization"), Hashed("IdentityLookup", "IdentityRoleName", HashIndexType.Unique, DataNormalization.None)] public override string? NormalizedName { get; set; }
}
#pragma warning restore CS1591
