using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;

namespace Mrbr.Encryption.Data.Identity;

/// <summary>
/// Model configuration for encrypted ASP.NET Core Identity entities.
/// </summary>
public static class IdentityModelBuilderExtensions
{
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
}
