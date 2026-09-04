using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;

namespace Mrbr.Encryption.Data.Identity;

/// <summary>
/// Model configuration for encrypted ASP.NET Core Identity entities.
/// </summary>
public static class IdentityModelBuilderExtensions
{
    /// <summary>Configures flattened protected passkey persistence.</summary>
    public static ModelBuilder ConfigureEncryptedIdentityPasskeys<TPasskey>(this ModelBuilder modelBuilder)
        where TPasskey : EncryptedIdentityUserPasskey
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);
        modelBuilder.Entity<TPasskey>(passkey =>
        {
            passkey.Ignore(value => value.CredentialId);
            passkey.Ignore(value => value.Data);
            passkey.HasKey(value => value.PasskeyId);
            passkey.Property(value => value.PasskeyId).ValueGeneratedNever();
            passkey.Property(value => value.RoutingHash).HasMaxLength(128).IsRequired();
            passkey.HasIndex(value => value.RoutingHash).IsUnique();
            passkey.HasIndex(value => value.UserId);
        });
        return modelBuilder;
    }

    /// <summary>Replaces Identity's plaintext external-login key with a UUIDv7 key and HMAC route.</summary>
    public static ModelBuilder ConfigureEncryptedIdentityLogins<TLogin>(this ModelBuilder modelBuilder)
        where TLogin : EncryptedIdentityUserLogin
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);
        modelBuilder.Entity<TLogin>(login =>
        {
            login.HasKey(value => value.LoginId);
            login.Property(value => value.LoginId).ValueGeneratedNever();
            login.Property(value => value.RoutingHash).HasMaxLength(128).IsRequired();
            login.HasIndex(value => value.RoutingHash).IsUnique();
            login.HasIndex(value => value.UserId);
        });
        return modelBuilder;
    }

    /// <summary>Configures indexed composite-HMAC routes for protected user and role claims.</summary>
    public static ModelBuilder ConfigureEncryptedIdentityClaims<TUserClaim, TRoleClaim>(this ModelBuilder modelBuilder)
        where TUserClaim : EncryptedIdentityUserClaim<string>
        where TRoleClaim : EncryptedIdentityRoleClaim<string>
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);

        modelBuilder.Entity<TUserClaim>(claim =>
        {
            claim.Property(value => value.RoutingHash).HasMaxLength(128).IsRequired();
            claim.HasIndex(value => value.RoutingHash);
            claim.HasIndex(value => value.UserId);
        });
        modelBuilder.Entity<TRoleClaim>(claim =>
        {
            claim.Property(value => value.RoutingHash).HasMaxLength(128).IsRequired();
            claim.HasIndex(value => value.RoutingHash);
            claim.HasIndex(value => value.RoleId);
        });

        return modelBuilder;
    }

    /// <summary>Replaces Identity's composite token key with UUIDv7 and composite-HMAC routing.</summary>
    public static ModelBuilder ConfigureEncryptedIdentityTokens<TToken>(this ModelBuilder modelBuilder)
        where TToken : EncryptedIdentityUserToken<string>
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);

        modelBuilder.Entity<TToken>(token =>
        {
            token.HasKey(value => value.TokenId);
            token.Property(value => value.TokenId).ValueGeneratedNever();
            token.Property(value => value.RoutingHash).HasMaxLength(128).IsRequired();
            token.HasIndex(value => value.RoutingHash).IsUnique();
            token.HasIndex(value => value.UserId);
        });

        return modelBuilder;
    }

    /// <summary>
    /// Removes Identity's conventional indexes over normalized username and email properties.
    /// Generated keyed-HMAC indexes should be configured after this call.
    /// </summary>
    public static ModelBuilder RemoveIdentityPlaintextLookupIndexes<TUser>(
        this ModelBuilder modelBuilder)
        where TUser : IdentityUser
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);

        IMutableEntityType userEntity = modelBuilder.Entity<TUser>().Metadata;
        foreach (IMutableIndex index in userEntity.GetIndexes()
                     .Where(static index => index.Properties.Any(static property =>
                         property.Name is nameof(IdentityUser.NormalizedUserName)
                             or nameof(IdentityUser.NormalizedEmail)))
                     .ToArray())
        {
            userEntity.RemoveIndex(index);
        }

        return modelBuilder;
    }

    /// <summary>Removes Identity's conventional normalized role-name index.</summary>
    public static ModelBuilder RemoveIdentityPlaintextRoleLookupIndex<TRole>(
        this ModelBuilder modelBuilder)
        where TRole : IdentityRole
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);

        IMutableEntityType roleEntity = modelBuilder.Entity<TRole>().Metadata;
        foreach (IMutableIndex index in roleEntity.GetIndexes()
                     .Where(static index => index.Properties.Any(static property =>
                         property.Name == nameof(IdentityRole.NormalizedName)))
                     .ToArray())
        {
            roleEntity.RemoveIndex(index);
        }

        return modelBuilder;
    }
}
