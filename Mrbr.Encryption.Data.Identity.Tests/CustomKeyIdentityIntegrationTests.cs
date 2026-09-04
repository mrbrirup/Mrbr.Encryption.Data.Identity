using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Mrbr.Encryption.Data.Common.Algorithms;
using Mrbr.Encryption.Data.EntityFramework.Extensions;
using Mrbr.Encryption.Data.EntityFramework.Services;
using Mrbr.Encryption.Data.Generated;
using Mrbr.Encryption.Data.GeneratedIdentity;
using System.Security.Claims;

namespace Mrbr.Encryption.Data.Identity.Tests;

public sealed class CustomKeyIdentityIntegrationTests
{
    [Fact]
    public async Task GuidKey_CreatesAndFindsProtectedUser()
    {
        await using SqliteConnection connection = new("Data Source=:memory:");
        await connection.OpenAsync();
        ServiceCollection services = Services();
        services.AddMrbrIdentityKeySerializer<Guid>();
        services.AddDbContext<GuidIdentityContext>((provider, options) =>
            options.UseSqlite(connection).AddMrbrEntityEncryption(provider));
        services.AddIdentityCore<GuidIdentityUser>().AddRoles<GuidIdentityRole>()
            .AddEntityFrameworkStores<GuidIdentityContext>().AddMrbrGeneratedIdentityStore<GuidIdentityContext>();
        await VerifyAsync<GuidIdentityContext, GuidIdentityUser, GuidIdentityRole, Guid>(services,
            new GuidIdentityUser { Id = Guid.NewGuid(), UserName = "guid-user", Email = "guid@example.test" },
            new GuidIdentityRole { Id = Guid.NewGuid(), Name = "guid-role" });
    }

    [Fact]
    public async Task IntegerKey_CreatesAndFindsProtectedUser()
    {
        await using SqliteConnection connection = new("Data Source=:memory:");
        await connection.OpenAsync();
        ServiceCollection services = Services();
        services.AddMrbrIdentityKeySerializer<long>();
        services.AddDbContext<LongIdentityContext>((provider, options) =>
            options.UseSqlite(connection).AddMrbrEntityEncryption(provider));
        services.AddIdentityCore<LongIdentityUser>().AddRoles<LongIdentityRole>()
            .AddEntityFrameworkStores<LongIdentityContext>().AddMrbrGeneratedIdentityStore<LongIdentityContext>();
        await VerifyAsync<LongIdentityContext, LongIdentityUser, LongIdentityRole, long>(services,
            new LongIdentityUser { Id = 42, UserName = "long-user", Email = "long@example.test" },
            new LongIdentityRole { Id = 84, Name = "long-role" });
    }

    [Fact]
    public async Task StronglyTypedKey_CreatesAndFindsProtectedUser()
    {
        await using SqliteConnection connection = new("Data Source=:memory:");
        await connection.OpenAsync();
        ServiceCollection services = Services();
        services.AddMrbrIdentityKeySerializer<TenantUserId, TenantUserIdSerializer>();
        services.AddDbContext<TenantIdentityContext>((provider, options) =>
            options.UseSqlite(connection).AddMrbrEntityEncryption(provider));
        services.AddIdentityCore<TenantIdentityUser>().AddRoles<TenantIdentityRole>()
            .AddEntityFrameworkStores<TenantIdentityContext>().AddMrbrGeneratedIdentityStore<TenantIdentityContext>();
        await VerifyAsync<TenantIdentityContext, TenantIdentityUser, TenantIdentityRole, TenantUserId>(services,
            new TenantIdentityUser { Id = new TenantUserId(Guid.NewGuid()), UserName = "tenant-user", Email = "tenant@example.test" },
            new TenantIdentityRole { Id = new TenantUserId(Guid.NewGuid()), Name = "tenant-role" });
    }

    private static ServiceCollection Services()
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddSingleton<IEntityDataProtectionService, TestProtectionService>();
        services.AddMrbrEntityEncryption();
        services.AddSingleton(new SourceKeyMapConfig
        {
            IdentityPII = Config(1, true, true), IdentityLookup = Config(2, false, true),
            IdentityCredential = Config(3, true, false), IdentityOperational = Config(4, true, false),
            IdentityAuthorization = Config(5, true, false),
            IdentityExternalLogin = Config(6, true, false), IdentityPasskey = Config(7, true, false),
            IdentityToken = Config(8, true, false), IdentityTokenLookup = Config(9, false, true)
        });
        return services;
    }

    private static SourceKeyConfig Config(byte id, bool encryption, bool hashing) => new()
    {
        SourceKeyId = id,
        EncryptionAlgorithm = encryption ? DataEncryptionAlgorithm.Aes256 : null,
        HashAlgorithm = hashing ? DataHashAlgorithm.HmacSha256 : null,
        SearchKeyHandles = hashing ? new Dictionary<string, ulong>
        {
            ["IdentityUserName"] = id, ["IdentityEmail"] = id, ["IdentityRoleName"] = id,
            ["IdentityTokenLookup"] = id, ["IdentityClaimRoute"] = id,
            ["IdentityLoginRoute"] = id, ["IdentityPasskeyCredential"] = id
        } : null
    };

    private static async Task VerifyAsync<TContext, TUser, TRole, TKey>(ServiceCollection services, TUser user, TRole role)
        where TContext : DbContext where TUser : IdentityUser<TKey> where TRole : IdentityRole<TKey> where TKey : IEquatable<TKey>
    {
        await using ServiceProvider provider = services.BuildServiceProvider();
        await using AsyncServiceScope scope = provider.CreateAsyncScope();
        TContext context = scope.ServiceProvider.GetRequiredService<TContext>();
        await context.Database.EnsureCreatedAsync();
        UserManager<TUser> manager = scope.ServiceProvider.GetRequiredService<UserManager<TUser>>();
        Assert.True((await manager.CreateAsync(user)).Succeeded);
        context.ChangeTracker.Clear();
        TUser? byName = await manager.FindByNameAsync(user.UserName!);
        TUser? byEmail = await manager.FindByEmailAsync(user.Email!);
        Assert.NotNull(byName);
        Assert.NotNull(byEmail);
        Assert.Equal(user.Id, byName.Id);
        Assert.Equal(user.Id, byEmail.Id);
        user = byName;

        await manager.SetAuthenticationTokenAsync(user, "custom-provider", "refresh", "custom-token");
        Assert.Equal("custom-token", await manager.GetAuthenticationTokenAsync(user, "custom-provider", "refresh"));

        Claim userClaim = new("permission", "read");
        Assert.True((await manager.AddClaimAsync(user, userClaim)).Succeeded);
        Assert.Contains(await manager.GetClaimsAsync(user), value => value.Type == userClaim.Type && value.Value == userClaim.Value);

        UserLoginInfo login = new("custom-login", "provider-key", "Custom login");
        Assert.True((await manager.AddLoginAsync(user, login)).Succeeded);
        Assert.Equal(user.Id, (await manager.FindByLoginAsync(login.LoginProvider, login.ProviderKey))!.Id);

        byte[] credentialId = [1, 3, 5, 7];
        UserPasskeyInfo passkey = new(credentialId, [2, 4, 6], DateTimeOffset.UtcNow, 1, ["internal"],
            true, true, false, [8, 10], [12, 14]) { Name = "Custom key" };
        Assert.True((await manager.AddOrUpdatePasskeyAsync(user, passkey)).Succeeded);
        Assert.Equal(user.Id, (await manager.FindByPasskeyIdAsync(credentialId))!.Id);
        Assert.Equal("Custom key", (await manager.GetPasskeyAsync(user, credentialId))!.Name);

        RoleManager<TRole> roles = scope.ServiceProvider.GetRequiredService<RoleManager<TRole>>();
        Assert.True((await roles.CreateAsync(role)).Succeeded);
        Claim roleClaim = new("scope", "custom");
        Assert.True((await roles.AddClaimAsync(role, roleClaim)).Succeeded);
        Assert.Contains(await roles.GetClaimsAsync(role), value => value.Type == roleClaim.Type && value.Value == roleClaim.Value);

        Claim replacement = new("permission", "write");
        Assert.True((await manager.ReplaceClaimAsync(user, userClaim, replacement)).Succeeded);
        Assert.Contains(await manager.GetClaimsAsync(user), value => value.Type == replacement.Type && value.Value == replacement.Value);
        Assert.True((await manager.RemoveClaimAsync(user, replacement)).Succeeded);
        Assert.True((await roles.RemoveClaimAsync(role, roleClaim)).Succeeded);
        Assert.True((await manager.RemoveLoginAsync(user, login.LoginProvider, login.ProviderKey)).Succeeded);
        Assert.Null(await manager.FindByLoginAsync(login.LoginProvider, login.ProviderKey));
        Assert.True((await manager.RemovePasskeyAsync(user, credentialId)).Succeeded);
        Assert.Null(await manager.FindByPasskeyIdAsync(credentialId));
        await manager.RemoveAuthenticationTokenAsync(user, "custom-provider", "refresh");
        Assert.Null(await manager.GetAuthenticationTokenAsync(user, "custom-provider", "refresh"));
    }
}

internal sealed class TenantUserIdSerializer : IIdentityKeySerializer<TenantUserId>
{
    public string Serialize(TenantUserId key) => key.Value.ToString("D").ToLowerInvariant();
}
