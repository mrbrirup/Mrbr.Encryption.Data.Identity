using System.Data.Common;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Mrbr.Encryption.Data.Common.Algorithms;
using Mrbr.Encryption.Data.Common.Attributes;
using Mrbr.Encryption.Data.Common.Models;
using Mrbr.Encryption.Data.Common.Results;
using Mrbr.Encryption.Data.EntityFramework.Services;
using Mrbr.Encryption.Data.Generated;
using Mrbr.Encryption.Data.GeneratedIdentity;
using Mrbr.Encryption.Data.Identity.Migration;
using Mrbr.Encryption.Data.Identity.Migration.Sqlite;

namespace Mrbr.Encryption.Data.Identity.Tests;

public sealed class GeneratedEncryptedIdentityTokenWorkflowTests
{
    [Fact]
    public async Task GeneratedRuntimeVerifier_GatesWritesAndExplicitPlaintextRemoval()
    {
        string databasePath = Path.Combine(Path.GetTempPath(), $"mrbr-generated-migration-{Guid.NewGuid():N}.db");
        string connectionString = $"Data Source={databasePath};Foreign Keys=True;Pooling=False";
        try
        {
            await CreateLegacyTokenDatabaseAsync(connectionString);
            ServiceCollection services = new();
            services.AddLogging();
            services.AddSingleton<IEntityDataProtectionService, TestProtectionService>();
            services.AddSingleton(CreateSourceKeyMap());
            services.AddDbContext<GeneratedTokenContext>(options => options.UseSqlite(connectionString));
            services.AddIdentityCore<GeneratedUser>()
                .AddRoles<IdentityRole>()
                .AddEntityFrameworkStores<GeneratedTokenContext>()
                .AddMrbrGeneratedIdentityStore<GeneratedTokenContext>();
            services.AddMrbrGeneratedIdentityTokenMigrationAdapter<GeneratedTokenContext>();

            await using ServiceProvider provider = services.BuildServiceProvider();
            await using AsyncServiceScope scope = provider.CreateAsyncScope();
            IIdentityTokenMigrationProtectionAdapter protection = scope.ServiceProvider
                .GetRequiredService<IIdentityTokenMigrationProtectionAdapter>();
            IIdentityTokenMigrationRuntimeVerifier runtimeVerifier = scope.ServiceProvider
                .GetRequiredService<IIdentityTokenMigrationRuntimeVerifier>();
            Guid migrationId = Guid.CreateVersion7();
            SqliteIdentityTokenMigrationCheckpointStore checkpoints = new(connectionString);
            IdentityTokenMigrationCheckpoint checkpoint = AssertMigrationSuccess(
                IdentityTokenMigrationStateMachine.Create(migrationId, expectedSourceRows: 1));
            checkpoint = AssertMigrationSuccess(IdentityTokenMigrationStateMachine.Advance(
                checkpoint,
                IdentityTokenMigrationStage.PreflightPassed,
                0,
                0,
                0));
            await checkpoints.SaveAsync(checkpoint, CancellationToken.None);
            SqliteIdentityTokenMigrationSchemaExecutor schema = new(connectionString, migrationId);
            checkpoint = AssertMigrationSuccess(await schema.CreateShadowSchemaAsync(checkpoint, checkpoints));
            checkpoint = AssertMigrationSuccess(IdentityTokenMigrationStateMachine.Advance(
                checkpoint,
                IdentityTokenMigrationStage.BackfillInProgress,
                0,
                0,
                0));
            await checkpoints.SaveAsync(checkpoint, CancellationToken.None);
            SqliteIdentityTokenMigrationSource source = new(connectionString);
            SqliteIdentityTokenMigrationBatchProcessor processor = new(connectionString, migrationId, protection);
            checkpoint = AssertMigrationSuccess(await IdentityTokenMigrationCoordinator.BackfillAsync(
                checkpoint,
                source,
                processor,
                checkpoints,
                new IdentityTokenMigrationOptions { BatchSize = 1 }));
            checkpoint = AssertMigrationSuccess(await IdentityTokenMigrationCoordinator.VerifyAsync(
                checkpoint,
                source,
                processor,
                checkpoints,
                new IdentityTokenMigrationOptions { BatchSize = 1 }));
            checkpoint = AssertMigrationSuccess(await schema.CutoverAsync(checkpoint, checkpoints));

            Assert.False(IdentityTokenMigrationStateMachine.AcceptProtectedWrites(checkpoint).IsSuccess);
            SqliteIdentityTokenMigrationSource retainedLegacy = new(connectionString, migrationId);
            checkpoint = AssertMigrationSuccess(await IdentityTokenMigrationCoordinator.VerifyRuntimeStoreAsync(
                checkpoint,
                retainedLegacy,
                runtimeVerifier,
                checkpoints,
                new IdentityTokenMigrationOptions { BatchSize = 1 }));
            Assert.Equal(IdentityTokenMigrationStage.RuntimeVerified, checkpoint.Stage);
            checkpoint = AssertMigrationSuccess(await IdentityTokenMigrationCoordinator.AcceptProtectedWritesAsync(
                checkpoint,
                checkpoints));

            IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint> rejected =
                await schema.RemoveRetainedPlaintextAsync(
                    checkpoint,
                    new IdentityTokenMigrationPlaintextRemovalApproval(
                        migrationId,
                        backupRetentionAddressed: true,
                        replicasAndExportsAddressed: false,
                        irreversibleRemovalApproved: true),
                    checkpoints);
            Assert.False(rejected.IsSuccess);
            Assert.Equal(IdentityTokenMigrationFailureCode.OperatorApprovalRequired, rejected.FailureCode);

            checkpoint = AssertMigrationSuccess(await schema.RemoveRetainedPlaintextAsync(
                checkpoint,
                new IdentityTokenMigrationPlaintextRemovalApproval(
                    migrationId,
                    backupRetentionAddressed: true,
                    replicasAndExportsAddressed: true,
                    irreversibleRemovalApproved: true),
                checkpoints));
            Assert.Equal(IdentityTokenMigrationStage.PlaintextRemoved, checkpoint.Stage);
            Assert.Equal(0, await CountNamedObjectAsync(
                connectionString,
                new SqliteIdentityTokenMigrationNames(migrationId).LegacyTable));
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            File.Delete(databasePath);
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("token-secret")]
    public async Task GeneratedMigrationAdapter_UsesRuntimeConfigurationAndVerifiesEveryField(string? tokenValue)
    {
        await using SqliteConnection connection = new("Data Source=:memory:");
        await connection.OpenAsync();
        ServiceCollection services = new();
        services.AddLogging();
        services.AddSingleton<IEntityDataProtectionService, TestProtectionService>();
        services.AddSingleton(CreateSourceKeyMap());
        services.AddDbContext<GeneratedTokenContext>(options => options.UseSqlite(connection));
        services.AddIdentityCore<GeneratedUser>()
            .AddRoles<IdentityRole>()
            .AddEntityFrameworkStores<GeneratedTokenContext>()
            .AddMrbrGeneratedIdentityStore<GeneratedTokenContext>();
        services.AddMrbrGeneratedIdentityTokenMigrationAdapter<GeneratedTokenContext>();

        await using ServiceProvider provider = services.BuildServiceProvider();
        await using AsyncServiceScope scope = provider.CreateAsyncScope();
        IIdentityTokenMigrationProtectionAdapter adapter = scope.ServiceProvider
            .GetRequiredService<IIdentityTokenMigrationProtectionAdapter>();
        LegacyIdentityTokenMigrationRow source = new("user-1", "provider", "purpose", tokenValue);

        IdentityTokenMigrationResult<string> hash = adapter.ComputeRoutingHash(source);
        Assert.True(hash.IsSuccess);
        Guid tokenId = Guid.CreateVersion7();
        IdentityTokenMigrationResult<ProtectedIdentityTokenMigrationRow> protectedResult = adapter.Protect(
            source,
            tokenId,
            hash.Value);

        Assert.True(protectedResult.IsSuccess);
        ProtectedIdentityTokenMigrationRow protectedRow = protectedResult.Value;
        Assert.Equal(tokenId, protectedRow.TokenId);
        AssertProtected(protectedRow.EncryptedLoginProvider, source.LoginProvider);
        AssertProtected(protectedRow.EncryptedName, source.Name);
        if (source.Value is null)
        {
            Assert.Null(protectedRow.EncryptedValue);
        }
        else
        {
            Assert.StartsWith("protected:", Assert.IsType<string>(protectedRow.EncryptedValue), StringComparison.Ordinal);
        }
        IdentityTokenMigrationResult<bool> verified = adapter.Verify(source, protectedRow);
        Assert.True(verified.IsSuccess);
        Assert.True(verified.Value);

        LegacyIdentityTokenMigrationRow altered = new("user-1", "provider", "purpose", "different-secret");
        IdentityTokenMigrationResult<bool> mismatch = adapter.Verify(altered, protectedRow);
        Assert.True(mismatch.IsSuccess);
        Assert.False(mismatch.Value);

        ProtectedIdentityTokenMigrationRow malformed = new(
            protectedRow.TokenId,
            protectedRow.UserId,
            "protected:not-base64",
            protectedRow.EncryptedName,
            protectedRow.EncryptedValue,
            protectedRow.RoutingHash);
        IdentityTokenMigrationResult<bool> invalid = adapter.Verify(source, malformed);
        Assert.False(invalid.IsSuccess);
        Assert.Equal(IdentityTokenMigrationFailureCode.InvalidPayload, invalid.FailureCode);
    }

    [Fact]
    public async Task GeneratedStore_ProtectsAndFindsIdentityTokenInSqlite()
    {
        await using SqliteConnection connection = new("Data Source=:memory:");
        await connection.OpenAsync();
        ServiceCollection services = new();
        services.AddLogging();
        services.AddSingleton<IEntityDataProtectionService, TestProtectionService>();
        services.AddSingleton(CreateSourceKeyMap());
        services.AddDbContext<GeneratedTokenContext>(options => options.UseSqlite(connection));
        services.AddIdentityCore<GeneratedUser>()
            .AddRoles<IdentityRole>()
            .AddEntityFrameworkStores<GeneratedTokenContext>()
            .AddMrbrGeneratedIdentityStore<GeneratedTokenContext>();

        await using ServiceProvider provider = services.BuildServiceProvider();
        await using AsyncServiceScope scope = provider.CreateAsyncScope();
        GeneratedTokenContext context = scope.ServiceProvider.GetRequiredService<GeneratedTokenContext>();
        await context.Database.EnsureCreatedAsync();
        UserManager<GeneratedUser> users = scope.ServiceProvider.GetRequiredService<UserManager<GeneratedUser>>();
        GeneratedUser user = new() { UserName = "alice", Email = "alice@example.test" };
        Assert.True((await users.CreateAsync(user)).Succeeded);

        await users.SetAuthenticationTokenAsync(user, "provider", "purpose", "token-secret");
        Assert.Equal(
            "token-secret",
            await users.GetAuthenticationTokenAsync(user, "provider", "purpose"));

        context.ChangeTracker.Clear();
        await using DbCommand command = connection.CreateCommand();
        command.CommandText = "SELECT TokenId, LoginProvider, Name, Value, RoutingHash FROM AspNetUserTokens";
        await using DbDataReader reader = await command.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        Assert.Equal(7, Guid.Parse(reader.GetString(0)).Version);
        AssertProtected(reader.GetString(1), "provider");
        AssertProtected(reader.GetString(2), "purpose");
        AssertProtected(reader.GetString(3), "token-secret");
        Assert.Equal(64, reader.GetString(4).Length);
    }

    [Theory]
    [InlineData("LoginProvider")]
    [InlineData("Name")]
    [InlineData("Value")]
    public async Task GeneratedStore_TranslatesTamperedTokenColumnsWithoutTreatingThemAsMissing(string column)
    {
        await using SqliteConnection connection = new("Data Source=:memory:");
        await connection.OpenAsync();
        ServiceCollection services = new();
        services.AddLogging();
        services.AddSingleton<IEntityDataProtectionService, TestProtectionService>();
        services.AddSingleton(CreateSourceKeyMap());
        services.AddDbContext<GeneratedTokenContext>(options => options.UseSqlite(connection));
        services.AddIdentityCore<GeneratedUser>()
            .AddRoles<IdentityRole>()
            .AddEntityFrameworkStores<GeneratedTokenContext>()
            .AddMrbrGeneratedIdentityStore<GeneratedTokenContext>();

        await using ServiceProvider provider = services.BuildServiceProvider();
        await using AsyncServiceScope scope = provider.CreateAsyncScope();
        GeneratedTokenContext context = scope.ServiceProvider.GetRequiredService<GeneratedTokenContext>();
        await context.Database.EnsureCreatedAsync();
        UserManager<GeneratedUser> users = scope.ServiceProvider.GetRequiredService<UserManager<GeneratedUser>>();
        GeneratedUser user = new() { UserName = "alice", Email = "alice@example.test" };
        Assert.True((await users.CreateAsync(user)).Succeeded);
        await users.SetAuthenticationTokenAsync(user, "provider", "purpose", "token-secret");

        await using (DbCommand tamper = connection.CreateCommand())
        {
            tamper.CommandText = $"UPDATE AspNetUserTokens SET {column} = 'protected:not-base64'";
            Assert.Equal(1, await tamper.ExecuteNonQueryAsync());
        }

        context.ChangeTracker.Clear();
        IdentityDataProtectionException exception = await Assert.ThrowsAsync<IdentityDataProtectionException>(
            () => users.GetAuthenticationTokenAsync(user, "provider", "purpose"));

        Assert.Equal(ProtectionFailureCode.InvalidPayload, exception.FailureCode);
        Assert.DoesNotContain("provider", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("token-secret", exception.Message, StringComparison.Ordinal);
    }

    private static SourceKeyMapConfig CreateSourceKeyMap() => new()
    {
        IdentityPII = Config(1, encryption: true, hashing: true),
        IdentityToken = Config(2, encryption: true, hashing: false),
        IdentityCredential = Config(3, encryption: true, hashing: false),
        IdentityTokenLookup = Config(4, encryption: false, hashing: true)
    };

    private static SourceKeyConfig Config(int id, bool encryption, bool hashing) => new()
    {
        SourceKeyId = id,
        EncryptionAlgorithm = encryption ? DataEncryptionAlgorithm.Aes256 : null,
        HashAlgorithm = hashing ? DataHashAlgorithm.HmacSha256 : null,
        SearchKeyHandle = hashing ? checked((ulong)id) : null
    };

    private static void AssertProtected(string stored, string plaintext)
    {
        Assert.StartsWith("protected:", stored, StringComparison.Ordinal);
        Assert.DoesNotContain(plaintext, stored, StringComparison.Ordinal);
    }

    private static T AssertMigrationSuccess<T>(IdentityTokenMigrationResult<T> result)
    {
        Assert.True(result.IsSuccess, $"Expected migration success, received {result.FailureCode}.");
        return result.Value;
    }

    private static async Task CreateLegacyTokenDatabaseAsync(string connectionString)
    {
        await using SqliteConnection connection = new(connectionString);
        await connection.OpenAsync();
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            "CREATE TABLE \"AspNetUsers\" (\"Id\" TEXT NOT NULL PRIMARY KEY);" +
            "CREATE TABLE \"AspNetUserTokens\" (" +
            "\"UserId\" TEXT NOT NULL, \"LoginProvider\" TEXT NOT NULL, \"Name\" TEXT NOT NULL, \"Value\" TEXT NULL, " +
            "CONSTRAINT \"PK_AspNetUserTokens\" PRIMARY KEY (\"UserId\", \"LoginProvider\", \"Name\"), " +
            "CONSTRAINT \"FK_AspNetUserTokens_AspNetUsers_UserId\" FOREIGN KEY (\"UserId\") " +
            "REFERENCES \"AspNetUsers\" (\"Id\") ON DELETE CASCADE);" +
            "INSERT INTO \"AspNetUsers\" (\"Id\") VALUES ('user-1');" +
            "INSERT INTO \"AspNetUserTokens\" (\"UserId\", \"LoginProvider\", \"Name\", \"Value\") " +
            "VALUES ('user-1', 'provider', 'purpose', 'token-secret');";
        await command.ExecuteNonQueryAsync();
    }

    private static async Task<long> CountNamedObjectAsync(string connectionString, string objectName)
    {
        await using SqliteConnection connection = new(connectionString);
        await connection.OpenAsync();
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE name = $name";
        command.Parameters.AddWithValue("$name", objectName);
        return Convert.ToInt64(await command.ExecuteScalarAsync(), CultureInfo.InvariantCulture);
    }
}

internal sealed class GeneratedUser : IdentityUser
{
    [Encrypted("IdentityPII")]
    public override string? UserName { get; set; }

    [Encrypted("IdentityPII")]
    [Hashed("IdentityPII", Normalization = DataNormalization.None, IsUnique = true)]
    public override string? NormalizedUserName { get; set; }

    [Encrypted("IdentityPII")]
    public override string? Email { get; set; }

    [Encrypted("IdentityPII")]
    [Hashed("IdentityPII", Normalization = DataNormalization.None, IsUnique = false)]
    public override string? NormalizedEmail { get; set; }
}

internal sealed class GeneratedUserToken : EncryptedIdentityUserToken<string>
{
    [Encrypted("IdentityToken")]
    public override string LoginProvider { get; set; } = null!;

    [Encrypted("IdentityToken")]
    public override string Name { get; set; } = null!;

    [Encrypted("IdentityCredential")]
    public override string? Value { get; set; }
}

[GenerateEncryptedIdentityLookup]
[GenerateEncryptedIdentityTokenStore("IdentityTokenLookup")]
[GenerateEncryptedIdentityTokenMigrationAdapter]
internal sealed class GeneratedTokenContext(
    DbContextOptions<GeneratedTokenContext> options,
    IEntityDataProtectionService dataProtectionService,
    SourceKeyMapConfig sourceKeyMapConfig)
    : IdentityDbContext<
        GeneratedUser,
        IdentityRole,
        string,
        IdentityUserClaim<string>,
        IdentityUserRole<string>,
        IdentityUserLogin<string>,
        IdentityRoleClaim<string>,
        GeneratedUserToken,
        IdentityUserPasskey<string>>(options)
{
    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.RemoveIdentityPlaintextLookupIndexes<GeneratedUser>();
        builder.AddMrbrGeneratedEncryption(dataProtectionService, sourceKeyMapConfig);
    }
}

internal sealed class TestProtectionService : IEntityDataProtectionService
{
    public string Encrypt(string plainText, EncryptedPropertyConfiguration configuration) =>
        "protected:" + Convert.ToBase64String(Encoding.UTF8.GetBytes(plainText));

    public string Decrypt(string encryptedText, EncryptedPropertyConfiguration configuration) =>
        Encoding.UTF8.GetString(Convert.FromBase64String(encryptedText["protected:".Length..]));

    public string ComputeSearchHash(string value, HashedPropertyConfiguration configuration) =>
        Hash(Encoding.UTF8.GetBytes(value));

    public ProtectionResult<string> ComputeCompositeSearchHash(
        string domain,
        IReadOnlyList<string> values,
        HashedPropertyConfiguration configuration)
    {
        byte[] input = CompositeHashInputEncoder.Encode(domain, values);
        try
        {
            return ProtectionResult<string>.Success(Hash(input));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
        }
    }

    private static string Hash(byte[] input)
    {
        byte[] hash = SHA256.HashData(input);
        try
        {
            return Convert.ToHexString(hash);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hash);
            CryptographicOperations.ZeroMemory(input);
        }
    }
}
