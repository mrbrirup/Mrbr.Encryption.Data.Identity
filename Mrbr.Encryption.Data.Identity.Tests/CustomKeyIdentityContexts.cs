using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Mrbr.Encryption.Data.Common.Attributes;
using Mrbr.Encryption.Data.EntityFramework.Services;
using Mrbr.Encryption.Data.Generated;

namespace Mrbr.Encryption.Data.Identity.Tests;

internal sealed class GuidIdentityUser : EncryptedIdentityUser<Guid>;
internal sealed class GuidIdentityRole : EncryptedIdentityRole<Guid>;
internal sealed class GuidIdentityUserClaim : EncryptedIdentityUserClaim<Guid>;
internal sealed class GuidIdentityRoleClaim : EncryptedIdentityRoleClaim<Guid>;
internal sealed class GuidIdentityUserLogin : EncryptedIdentityUserLogin<Guid>;
internal sealed class GuidIdentityUserToken : EncryptedIdentityUserToken<Guid>;
internal sealed class GuidIdentityUserPasskey : EncryptedIdentityUserPasskey<Guid>;

[GenerateEncryptedIdentityLookup]
[GenerateEncryptedIdentityTokenStore("IdentityTokenLookup")]
[GenerateEncryptedIdentityClaimStores("IdentityTokenLookup")]
[GenerateEncryptedIdentityLoginStore("IdentityTokenLookup")]
[GenerateEncryptedIdentityPasskeyStore("IdentityTokenLookup")]
internal sealed class GuidIdentityContext(
    DbContextOptions<GuidIdentityContext> options,
    IEntityDataProtectionService protection,
    SourceKeyMapConfig config) : IdentityDbContext<
        GuidIdentityUser, GuidIdentityRole, Guid,
        GuidIdentityUserClaim, IdentityUserRole<Guid>, GuidIdentityUserLogin,
        GuidIdentityRoleClaim, GuidIdentityUserToken, GuidIdentityUserPasskey>(options)
{
    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.ConfigureEncryptedIdentityClaims<Guid, GuidIdentityUserClaim, GuidIdentityRoleClaim>();
        builder.ConfigureEncryptedIdentityLogins<Guid, GuidIdentityUserLogin>();
        builder.ConfigureEncryptedIdentityPasskeys<Guid, GuidIdentityUserPasskey>();
        builder.AddMrbrGeneratedEncryption(protection, config);
    }
}

internal sealed class LongIdentityUser : EncryptedIdentityUser<long>;
internal sealed class LongIdentityRole : EncryptedIdentityRole<long>;
internal sealed class LongIdentityUserClaim : EncryptedIdentityUserClaim<long>;
internal sealed class LongIdentityRoleClaim : EncryptedIdentityRoleClaim<long>;
internal sealed class LongIdentityUserLogin : EncryptedIdentityUserLogin<long>;
internal sealed class LongIdentityUserToken : EncryptedIdentityUserToken<long>;
internal sealed class LongIdentityUserPasskey : EncryptedIdentityUserPasskey<long>;

[GenerateEncryptedIdentityLookup]
[GenerateEncryptedIdentityTokenStore("IdentityTokenLookup")]
[GenerateEncryptedIdentityClaimStores("IdentityTokenLookup")]
[GenerateEncryptedIdentityLoginStore("IdentityTokenLookup")]
[GenerateEncryptedIdentityPasskeyStore("IdentityTokenLookup")]
internal sealed class LongIdentityContext(
    DbContextOptions<LongIdentityContext> options,
    IEntityDataProtectionService protection,
    SourceKeyMapConfig config) : IdentityDbContext<
        LongIdentityUser, LongIdentityRole, long,
        LongIdentityUserClaim, IdentityUserRole<long>, LongIdentityUserLogin,
        LongIdentityRoleClaim, LongIdentityUserToken, LongIdentityUserPasskey>(options)
{
    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.ConfigureEncryptedIdentityClaims<long, LongIdentityUserClaim, LongIdentityRoleClaim>();
        builder.ConfigureEncryptedIdentityLogins<long, LongIdentityUserLogin>();
        builder.ConfigureEncryptedIdentityPasskeys<long, LongIdentityUserPasskey>();
        builder.AddMrbrGeneratedEncryption(protection, config);
    }
}

internal readonly record struct TenantUserId(Guid Value);

internal sealed class TenantIdentityUser : EncryptedIdentityUser<TenantUserId>;
internal sealed class TenantIdentityRole : EncryptedIdentityRole<TenantUserId>;
internal sealed class TenantIdentityUserClaim : EncryptedIdentityUserClaim<TenantUserId>;
internal sealed class TenantIdentityRoleClaim : EncryptedIdentityRoleClaim<TenantUserId>;
internal sealed class TenantIdentityUserLogin : EncryptedIdentityUserLogin<TenantUserId>;
internal sealed class TenantIdentityUserToken : EncryptedIdentityUserToken<TenantUserId>;
internal sealed class TenantIdentityUserPasskey : EncryptedIdentityUserPasskey<TenantUserId>;

[GenerateEncryptedIdentityLookup]
[GenerateEncryptedIdentityTokenStore("IdentityTokenLookup")]
[GenerateEncryptedIdentityClaimStores("IdentityTokenLookup")]
[GenerateEncryptedIdentityLoginStore("IdentityTokenLookup")]
[GenerateEncryptedIdentityPasskeyStore("IdentityTokenLookup")]
internal sealed class TenantIdentityContext(
    DbContextOptions<TenantIdentityContext> options,
    IEntityDataProtectionService protection,
    SourceKeyMapConfig config) : IdentityDbContext<
        TenantIdentityUser, TenantIdentityRole, TenantUserId,
        TenantIdentityUserClaim, IdentityUserRole<TenantUserId>, TenantIdentityUserLogin,
        TenantIdentityRoleClaim, TenantIdentityUserToken, TenantIdentityUserPasskey>(options)
{
    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.ConfigureEncryptedIdentityClaims<TenantUserId, TenantIdentityUserClaim, TenantIdentityRoleClaim>();
        builder.ConfigureEncryptedIdentityLogins<TenantUserId, TenantIdentityUserLogin>();
        builder.ConfigureEncryptedIdentityPasskeys<TenantUserId, TenantIdentityUserPasskey>();
        foreach (var entity in builder.Model.GetEntityTypes())
        {
            foreach (var property in entity.GetProperties().Where(value => value.ClrType == typeof(TenantUserId)))
            {
                property.SetValueConverter(new Microsoft.EntityFrameworkCore.Storage.ValueConversion.ValueConverter<TenantUserId, Guid>(
                    value => value.Value,
                    value => new TenantUserId(value)));
            }
        }
        builder.AddMrbrGeneratedEncryption(protection, config);
    }
}
