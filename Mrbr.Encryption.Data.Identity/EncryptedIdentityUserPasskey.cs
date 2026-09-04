using Microsoft.AspNetCore.Identity;
using Mrbr.Encryption.Data.Common.Attributes;

namespace Mrbr.Encryption.Data.Identity;

/// <summary>A flattened, provider-neutral passkey record whose fields are protected independently.</summary>
public class EncryptedIdentityUserPasskey : IdentityUserPasskey<string>
{
    /// <summary>Initializes a passkey with an application-generated RFC 9562 version 7 identifier.</summary>
    public EncryptedIdentityUserPasskey() => PasskeyId = Guid.CreateVersion7();

    /// <summary>Gets or sets the surrogate relational primary key.</summary>
    public Guid PasskeyId { get; set; }

    /// <summary>Gets or sets the encrypted credential identifier.</summary>
    [Encrypted("IdentityPasskey")]
    public byte[] ProtectedCredentialId { get; set; } = [];

    /// <summary>Gets or sets the keyed credential lookup route.</summary>
    public string RoutingHash { get; set; } = null!;

    /// <summary>Gets or sets the credential public key.</summary>
    [Encrypted("IdentityPasskey")] public byte[] PublicKey { get; set; } = [];
    /// <summary>Gets or sets the user-facing passkey name.</summary>
    [Encrypted("IdentityPasskey")] public string? PasskeyName { get; set; }
    /// <summary>Gets or sets the creation timestamp.</summary>
    [Encrypted("IdentityPasskey")] public DateTimeOffset CreatedAt { get; set; }
    /// <summary>Gets or sets the signature counter.</summary>
    [Encrypted("IdentityPasskey")] public uint SignCount { get; set; }
    /// <summary>Gets or sets supported authenticator transports.</summary>
    [Encrypted("IdentityPasskey")] public string[] Transports { get; set; } = [];
    /// <summary>Gets or sets whether the user was verified.</summary>
    [Encrypted("IdentityPasskey")] public bool IsUserVerified { get; set; }
    /// <summary>Gets or sets whether backup is supported.</summary>
    [Encrypted("IdentityPasskey")] public bool IsBackupEligible { get; set; }
    /// <summary>Gets or sets whether the credential is backed up.</summary>
    [Encrypted("IdentityPasskey")] public bool IsBackedUp { get; set; }
    /// <summary>Gets or sets the attestation object.</summary>
    [Encrypted("IdentityPasskey")] public byte[] AttestationObject { get; set; } = [];
    /// <summary>Gets or sets collected client-data JSON bytes.</summary>
    [Encrypted("IdentityPasskey")] public byte[] ClientDataJson { get; set; } = [];
    /// <summary>Gets or sets the authenticator AAGUID.</summary>
    [Encrypted("IdentityPasskey")] public byte[] Aaguid { get; set; } = [];
}
