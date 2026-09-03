using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Mrbr.Encryption.Data.Common.Algorithms;
using Mrbr.Encryption.Data.EntityFramework.Services;
using Mrbr.Encryption.Data.Generated;
using Mrbr.Encryption.Data.GeneratedIdentity;
using Mrbr.Encryption.Data.Identity.Migration;
using Mrbr.Encryption.Data.Identity.Migration.PostgreSql;
using Npgsql;

namespace Mrbr.Encryption.Data.Identity.Tests;

[Collection(PostgreSqlCollection.Name)]
public sealed class PostgreSqlIdentityTokenMigrationTests
{
    [PostgreSqlFact]
    public async Task GeneratedAdapter_CompletesMigrationAndReconcilesTransactionalDdlCheckpointFailures()
    {
        await using PostgreSqlTestDatabase database = await PostgreSqlTestDatabase.CreateAsync();
        await CreateLegacyDatabaseAsync(database.ConnectionString);
        await using ServiceProvider provider = CreateProvider(database.ConnectionString);
        await using AsyncServiceScope scope = provider.CreateAsyncScope();
        IIdentityTokenMigrationProtectionAdapter protection = scope.ServiceProvider
            .GetRequiredService<IIdentityTokenMigrationProtectionAdapter>();
        IIdentityTokenMigrationRuntimeVerifier runtimeVerifier = scope.ServiceProvider
            .GetRequiredService<IIdentityTokenMigrationRuntimeVerifier>();
        Guid migrationId = Guid.CreateVersion7();
        var schema = new PostgreSqlIdentityTokenMigrationSchemaExecutor(database.ConnectionString, migrationId);
        var checkpoints = new PostgreSqlIdentityTokenMigrationCheckpointStore(database.ConnectionString);
        IdentityTokenMigrationResult<long> preflight = await schema.ValidatePreflightAsync();
        Assert.True(preflight.IsSuccess);
        Assert.Equal(1, preflight.Value);
        IdentityTokenMigrationCheckpoint checkpoint = AssertSuccess(
            IdentityTokenMigrationStateMachine.Create(migrationId, preflight.Value));
        checkpoint = AssertSuccess(IdentityTokenMigrationStateMachine.Advance(
            checkpoint, IdentityTokenMigrationStage.PreflightPassed, 0, 0, 0));
        await checkpoints.SaveAsync(checkpoint, CancellationToken.None);
        checkpoint = AssertSuccess(await schema.CreateShadowSchemaAsync(checkpoint, checkpoints));
        checkpoint = AssertSuccess(IdentityTokenMigrationStateMachine.Advance(
            checkpoint, IdentityTokenMigrationStage.BackfillInProgress, 0, 0, 0));
        await checkpoints.SaveAsync(checkpoint, CancellationToken.None);
        var source = new PostgreSqlIdentityTokenMigrationSource(database.ConnectionString);
        var processor = new PostgreSqlIdentityTokenMigrationBatchProcessor(
            database.ConnectionString, migrationId, protection);
        checkpoint = AssertSuccess(await IdentityTokenMigrationCoordinator.BackfillAsync(
            checkpoint, source, processor, checkpoints, new IdentityTokenMigrationOptions { BatchSize = 1 }));
        checkpoint = AssertSuccess(await IdentityTokenMigrationCoordinator.VerifyAsync(
            checkpoint, source, processor, checkpoints, new IdentityTokenMigrationOptions { BatchSize = 1 }));

        await Assert.ThrowsAsync<IOException>(async () =>
            await schema.CutoverAsync(checkpoint, new ThrowingCheckpointStore()));
        checkpoint = AssertSuccess(await schema.CutoverAsync(checkpoint, checkpoints));
        Assert.Equal(IdentityTokenMigrationStage.CutoverComplete, checkpoint.Stage);
        Assert.Equal("uuid", await ColumnTypeAsync(database.ConnectionString, "TokenId"));
        Assert.True(await IndexExistsAsync(database.ConnectionString, "IX_AspNetUserTokens_RoutingHash"));
        Assert.True(await IndexExistsAsync(database.ConnectionString, "IX_AspNetUserTokens_UserId"));

        var retained = new PostgreSqlIdentityTokenMigrationSource(database.ConnectionString, migrationId);
        checkpoint = AssertSuccess(await IdentityTokenMigrationCoordinator.VerifyRuntimeStoreAsync(
            checkpoint, retained, runtimeVerifier, checkpoints,
            new IdentityTokenMigrationOptions { BatchSize = 1 }));
        checkpoint = AssertSuccess(await IdentityTokenMigrationCoordinator.AcceptProtectedWritesAsync(
            checkpoint, checkpoints));
        var approval = new IdentityTokenMigrationPlaintextRemovalApproval(
            migrationId, backupRetentionAddressed: true, replicasAndExportsAddressed: true,
            irreversibleRemovalApproved: true);
        await Assert.ThrowsAsync<IOException>(async () =>
            await schema.RemoveRetainedPlaintextAsync(checkpoint, approval, new ThrowingCheckpointStore()));
        checkpoint = AssertSuccess(await schema.RemoveRetainedPlaintextAsync(checkpoint, approval, checkpoints));
        Assert.Equal(IdentityTokenMigrationStage.PlaintextRemoved, checkpoint.Stage);
        Assert.False(await TableExistsAsync(
            database.ConnectionString, new PostgreSqlIdentityTokenMigrationNames(migrationId).LegacyTable));
    }

    private static ServiceProvider CreateProvider(string connectionString)
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddSingleton<IEntityDataProtectionService, TestProtectionService>();
        services.AddSingleton(new SourceKeyMapConfig
        {
            IdentityPII = Config(1, true, true),
            IdentityToken = Config(2, true, false),
            IdentityCredential = Config(3, true, false),
            IdentityTokenLookup = Config(4, false, true)
        });
        services.AddDbContext<GeneratedTokenContext>(options => options.UseNpgsql(connectionString));
        services.AddIdentityCore<GeneratedUser>()
            .AddRoles<IdentityRole>()
            .AddEntityFrameworkStores<GeneratedTokenContext>()
            .AddMrbrGeneratedIdentityStore<GeneratedTokenContext>();
        services.AddMrbrGeneratedIdentityTokenMigrationAdapter<GeneratedTokenContext>();
        return services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateOnBuild = true,
            ValidateScopes = true
        });
    }

    private static SourceKeyConfig Config(int id, bool encryption, bool hashing) => new()
    {
        SourceKeyId = id,
        EncryptionAlgorithm = encryption ? DataEncryptionAlgorithm.Aes256 : null,
        HashAlgorithm = hashing ? DataHashAlgorithm.HmacSha256 : null,
        SearchKeyHandle = hashing ? checked((ulong)id) : null
    };

    private static async Task CreateLegacyDatabaseAsync(string connectionString)
    {
        await using NpgsqlConnection connection = new(connectionString);
        await connection.OpenAsync();
        await using NpgsqlCommand command = new(
            "CREATE TABLE \"AspNetUsers\" (\"Id\" text NOT NULL PRIMARY KEY);" +
            "CREATE TABLE \"AspNetUserTokens\" (" +
            "\"UserId\" text NOT NULL, \"LoginProvider\" text NOT NULL, \"Name\" text NOT NULL, \"Value\" text NULL, " +
            "CONSTRAINT \"PK_AspNetUserTokens\" PRIMARY KEY (\"UserId\", \"LoginProvider\", \"Name\"), " +
            "CONSTRAINT \"FK_AspNetUserTokens_AspNetUsers_UserId\" FOREIGN KEY (\"UserId\") " +
            "REFERENCES \"AspNetUsers\" (\"Id\") ON DELETE CASCADE);" +
            "INSERT INTO \"AspNetUsers\" (\"Id\") VALUES ('user-1');" +
            "INSERT INTO \"AspNetUserTokens\" (\"UserId\", \"LoginProvider\", \"Name\", \"Value\") " +
            "VALUES ('user-1', 'provider', 'purpose', 'postgres-secret');",
            connection);
        await command.ExecuteNonQueryAsync();
    }

    private static async Task<string> ColumnTypeAsync(string connectionString, string column)
    {
        await using NpgsqlConnection connection = new(connectionString);
        await connection.OpenAsync();
        await using NpgsqlCommand command = new(
            "SELECT data_type FROM information_schema.columns WHERE table_schema = current_schema() " +
            "AND table_name = 'AspNetUserTokens' AND column_name = @column", connection);
        command.Parameters.AddWithValue("column", column);
        return (string)(await command.ExecuteScalarAsync() ?? throw new InvalidOperationException());
    }

    private static async Task<bool> IndexExistsAsync(string connectionString, string index)
    {
        await using NpgsqlConnection connection = new(connectionString);
        await connection.OpenAsync();
        await using NpgsqlCommand command = new(
            "SELECT to_regclass(format('%I.%I', current_schema(), @index)) IS NOT NULL", connection);
        command.Parameters.AddWithValue("index", index);
        return (bool)(await command.ExecuteScalarAsync() ?? false);
    }

    private static async Task<bool> TableExistsAsync(string connectionString, string table)
    {
        await using NpgsqlConnection connection = new(connectionString);
        await connection.OpenAsync();
        await using NpgsqlCommand command = new(
            "SELECT to_regclass(format('%I.%I', current_schema(), @table)) IS NOT NULL", connection);
        command.Parameters.AddWithValue("table", table);
        return (bool)(await command.ExecuteScalarAsync() ?? false);
    }

    private static T AssertSuccess<T>(IdentityTokenMigrationResult<T> result)
    {
        Assert.True(result.IsSuccess, $"Expected success, received {result.FailureCode}.");
        return result.Value;
    }

    private sealed class ThrowingCheckpointStore : IIdentityTokenMigrationCheckpointStore
    {
        public ValueTask SaveAsync(IdentityTokenMigrationCheckpoint checkpoint, CancellationToken cancellationToken) =>
            throw new IOException("Injected checkpoint persistence failure.");
    }
}
