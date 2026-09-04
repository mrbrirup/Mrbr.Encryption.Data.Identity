using Microsoft.AspNetCore.Identity;
using Mrbr.Encryption.Data.Common.Attributes;
#pragma warning disable CS1591

namespace Mrbr.Encryption.Data.Identity;

/// <summary>A protected external login with an application-selected user key type.</summary>
public class EncryptedIdentityUserLogin<TKey> : IdentityUserLogin<TKey> where TKey : IEquatable<TKey>
{
    public EncryptedIdentityUserLogin() => LoginId = Guid.CreateVersion7();
    public Guid LoginId { get; set; }
    [Encrypted("IdentityExternalLogin")] public override string LoginProvider { get; set; } = null!;
    [Encrypted("IdentityExternalLogin")] public override string ProviderKey { get; set; } = null!;
    [Encrypted("IdentityExternalLogin")] public override string? ProviderDisplayName { get; set; }
    public string RoutingHash { get; set; } = null!;
}
#pragma warning restore CS1591
