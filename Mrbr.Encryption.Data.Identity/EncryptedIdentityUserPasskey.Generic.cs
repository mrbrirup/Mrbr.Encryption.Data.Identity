using Microsoft.AspNetCore.Identity;
using Mrbr.Encryption.Data.Common.Attributes;
#pragma warning disable CS1591

namespace Mrbr.Encryption.Data.Identity;

/// <summary>A flattened protected passkey with an application-selected user key type.</summary>
public class EncryptedIdentityUserPasskey<TKey> : IdentityUserPasskey<TKey> where TKey : IEquatable<TKey>
{
    public EncryptedIdentityUserPasskey() => PasskeyId = Guid.CreateVersion7();
    public Guid PasskeyId { get; set; }
    [Encrypted("IdentityPasskey")] public byte[] ProtectedCredentialId { get; set; } = [];
    public string RoutingHash { get; set; } = null!;
    [Encrypted("IdentityPasskey")] public byte[] PublicKey { get; set; } = [];
    [Encrypted("IdentityPasskey")] public string? PasskeyName { get; set; }
    [Encrypted("IdentityPasskey")] public DateTimeOffset CreatedAt { get; set; }
    [Encrypted("IdentityPasskey")] public uint SignCount { get; set; }
    [Encrypted("IdentityPasskey")] public string[] Transports { get; set; } = [];
    [Encrypted("IdentityPasskey")] public bool IsUserVerified { get; set; }
    [Encrypted("IdentityPasskey")] public bool IsBackupEligible { get; set; }
    [Encrypted("IdentityPasskey")] public bool IsBackedUp { get; set; }
    [Encrypted("IdentityPasskey")] public byte[] AttestationObject { get; set; } = [];
    [Encrypted("IdentityPasskey")] public byte[] ClientDataJson { get; set; } = [];
    [Encrypted("IdentityPasskey")] public byte[] Aaguid { get; set; } = [];
}
#pragma warning restore CS1591
