using Microsoft.AspNetCore.Identity;
using Mrbr.Encryption.Data.Common.Attributes;

namespace Mrbr.Encryption.Data.Identity;

/// <summary>A provider-neutral external login with an opaque surrogate key and protected route.</summary>
public class EncryptedIdentityUserLogin : IdentityUserLogin<string>
{
    /// <summary>Initializes a login with an application-generated RFC 9562 version 7 identifier.</summary>
    public EncryptedIdentityUserLogin() => LoginId = Guid.CreateVersion7();

    /// <summary>Gets or sets the surrogate relational primary key.</summary>
    public Guid LoginId { get; set; }

    /// <inheritdoc />
    [Encrypted("IdentityExternalLogin")]
    public override string LoginProvider { get; set; } = null!;

    /// <inheritdoc />
    [Encrypted("IdentityExternalLogin")]
    public override string ProviderKey { get; set; } = null!;

    /// <inheritdoc />
    [Encrypted("IdentityExternalLogin")]
    public override string? ProviderDisplayName { get; set; }

    /// <summary>Gets or sets the keyed composite route over provider and provider key.</summary>
    public string RoutingHash { get; set; } = null!;
}
