using Microsoft.AspNetCore.Identity;
using Mrbr.Encryption.Data.Common.Algorithms;
using Mrbr.Encryption.Data.Common.Attributes;

namespace Mrbr.Encryption.Data.Identity;

/// <summary>A reusable string-key Identity role with protected name storage and lookup.</summary>
public class EncryptedIdentityRole : IdentityRole
{
    /// <inheritdoc />
    [Encrypted("IdentityAuthorization")]
    public override string? Name { get; set; }

    /// <inheritdoc />
    [Encrypted("IdentityAuthorization")]
    [Hashed("IdentityLookup", "IdentityRoleName", HashIndexType.Unique, DataNormalization.None)]
    public override string? NormalizedName { get; set; }
}
