using Microsoft.AspNetCore.Identity;
using Mrbr.Encryption.Data.Common.Attributes;

namespace Mrbr.Encryption.Data.Identity;

/// <summary>An Identity token with a UUIDv7 relational key and generated protected routing hash.</summary>
public class EncryptedIdentityUserToken<TKey> : IdentityUserToken<TKey>
    where TKey : IEquatable<TKey>
{
    /// <summary>Initializes a token with an application-generated RFC 9562 version 7 identifier.</summary>
    public EncryptedIdentityUserToken()
    {
        TokenId = Guid.CreateVersion7();
    }

    /// <summary>Gets or sets the surrogate relational primary key.</summary>
    public Guid TokenId { get; set; }

    /// <summary>Gets or sets the generated composite keyed hash used only for candidate routing.</summary>
    public string RoutingHash { get; set; } = null!;

    /// <inheritdoc />
    [Encrypted("IdentityToken")]
    public override string LoginProvider { get; set; } = null!;

    /// <inheritdoc />
    [Encrypted("IdentityToken")]
    public override string Name { get; set; } = null!;

    /// <inheritdoc />
    [Encrypted("IdentityToken")]
    public override string? Value { get; set; }
}
