using System.Data.Common;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Mrbr.Encryption.Data.Common.Algorithms;
using Mrbr.Encryption.Data.EntityFramework.Services;
using Mrbr.Encryption.Data.Generated;
using Mrbr.Encryption.Data.GeneratedIdentity;
using Npgsql;

namespace Mrbr.Encryption.Data.Identity.Tests;

[Collection(PostgreSqlCollection.Name)]
public sealed class PostgreSqlEncryptedIdentityTokenTests
{
    [PostgreSqlFact]
    public async Task GeneratedStore_UsesUuidAndProtectedIndexedRouting()
    {
        await using PostgreSqlTestDatabase database = await PostgreSqlTestDatabase.CreateAsync();
        await using ServiceProvider provider = CreateProvider(database.ConnectionString);
        await using AsyncServiceScope scope = provider.CreateAsyncScope();
        GeneratedTokenContext context = scope.ServiceProvider.GetRequiredService<GeneratedTokenContext>();
        await context.Database.EnsureCreatedAsync();
        UserManager<GeneratedUser> users = scope.ServiceProvider.GetRequiredService<UserManager<GeneratedUser>>();
        GeneratedUser user = new() { UserName = "postgres.alice", Email = "postgres.alice@example.test" };
        Assert.True((await users.CreateAsync(user)).Succeeded);
        await users.SetAuthenticationTokenAsync(user, "ExampleProvider", "RefreshToken", "postgres-token-secret");
        Assert.Equal(
            "postgres-token-secret",
            await users.GetAuthenticationTokenAsync(user, "ExampleProvider", "RefreshToken"));

        context.ChangeTracker.Clear();
        await using NpgsqlConnection connection = new(database.ConnectionString);
        await connection.OpenAsync();
        string tokenIdType = await ScalarStringAsync(
            connection,
            "SELECT data_type FROM information_schema.columns " +
            "WHERE table_schema = 'public' AND table_name = 'AspNetUserTokens' AND column_name = 'TokenId'");
        Assert.Equal("uuid", tokenIdType);

        string routingHash;
        await using (NpgsqlCommand command = new(
            "SELECT \"TokenId\", \"LoginProvider\", \"Name\", \"Value\", \"RoutingHash\" " +
            "FROM \"AspNetUserTokens\" WHERE \"UserId\" = @userId",
            connection))
        {
            command.Parameters.AddWithValue("userId", user.Id);
            await using NpgsqlDataReader reader = await command.ExecuteReaderAsync();
            Assert.True(await reader.ReadAsync());
            Assert.Equal(7, reader.GetGuid(0).Version);
            AssertProtected(reader.GetString(1), "ExampleProvider");
            AssertProtected(reader.GetString(2), "RefreshToken");
            AssertProtected(reader.GetString(3), "postgres-token-secret");
            routingHash = reader.GetString(4);
            Assert.Equal(64, routingHash.Length);
        }

        string indexes = await ScalarStringAsync(
            connection,
            "SELECT string_agg(indexdef, E'\\n') FROM pg_indexes " +
            "WHERE schemaname = 'public' AND tablename = 'AspNetUserTokens'");
        Assert.Contains("CREATE UNIQUE INDEX \"IX_AspNetUserTokens_RoutingHash\"", indexes, StringComparison.Ordinal);
        Assert.Contains("CREATE INDEX \"IX_AspNetUserTokens_UserId\"", indexes, StringComparison.Ordinal);

        await using (NpgsqlCommand disableSequentialScan = new("SET enable_seqscan = off", connection))
        {
            await disableSequentialScan.ExecuteNonQueryAsync();
        }

        await using (NpgsqlCommand explain = new(
            "EXPLAIN (FORMAT TEXT) SELECT * FROM \"AspNetUserTokens\" WHERE \"RoutingHash\" = @hash",
            connection))
        {
            explain.Parameters.AddWithValue("hash", routingHash);
            var plan = new List<string>();
            await using NpgsqlDataReader reader = await explain.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                plan.Add(reader.GetString(0));
            }

            Assert.Contains(plan, line => line.Contains("IX_AspNetUserTokens_RoutingHash", StringComparison.Ordinal));
        }
    }

    [PostgreSqlFact]
    public async Task GeneratedStore_ConcurrentInsertPreservesOneLogicalRoute()
    {
        await using PostgreSqlTestDatabase database = await PostgreSqlTestDatabase.CreateAsync();
        using Barrier barrier = new(2);
        TokenRouteBarrierInterceptor interceptor = new(barrier);
        await using ServiceProvider provider = CreateProvider(database.ConnectionString, interceptor);
        string userId;
        await using (AsyncServiceScope setupScope = provider.CreateAsyncScope())
        {
            GeneratedTokenContext setup = setupScope.ServiceProvider.GetRequiredService<GeneratedTokenContext>();
            await setup.Database.EnsureCreatedAsync();
            GeneratedUser user = new() { UserName = "concurrent.alice", Email = "concurrent.alice@example.test" };
            UserManager<GeneratedUser> users = setupScope.ServiceProvider.GetRequiredService<UserManager<GeneratedUser>>();
            Assert.True((await users.CreateAsync(user)).Succeeded);
            userId = user.Id;
        }

        await using AsyncServiceScope firstScope = provider.CreateAsyncScope();
        await using AsyncServiceScope secondScope = provider.CreateAsyncScope();
        GeneratedTokenContext firstContext = firstScope.ServiceProvider.GetRequiredService<GeneratedTokenContext>();
        GeneratedTokenContext secondContext = secondScope.ServiceProvider.GetRequiredService<GeneratedTokenContext>();
        GeneratedUser firstUser = await firstContext.Users.SingleAsync(user => user.Id == userId);
        GeneratedUser secondUser = await secondContext.Users.SingleAsync(user => user.Id == userId);
        UserManager<GeneratedUser> firstUsers = firstScope.ServiceProvider.GetRequiredService<UserManager<GeneratedUser>>();
        UserManager<GeneratedUser> secondUsers = secondScope.ServiceProvider.GetRequiredService<UserManager<GeneratedUser>>();

        await Task.WhenAll(
            firstUsers.SetAuthenticationTokenAsync(firstUser, "provider", "purpose", "first"),
            secondUsers.SetAuthenticationTokenAsync(secondUser, "provider", "purpose", "second"));

        await using AsyncServiceScope verificationScope = provider.CreateAsyncScope();
        GeneratedTokenContext verification = verificationScope.ServiceProvider.GetRequiredService<GeneratedTokenContext>();
        List<GeneratedUserToken> rows = await verification.Set<GeneratedUserToken>().AsNoTracking().ToListAsync();
        GeneratedUserToken row = Assert.Single(rows);
        Assert.Equal(7, row.TokenId.Version);
        Assert.Contains(row.Value, new[] { "first", "second" });
    }

    private static ServiceProvider CreateProvider(
        string connectionString,
        DbCommandInterceptor? interceptor = null)
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddSingleton<IEntityDataProtectionService, TestProtectionService>();
        services.AddSingleton(CreateSourceKeyMap());
        services.AddDbContext<GeneratedTokenContext>(options =>
        {
            options.UseNpgsql(connectionString);
            if (interceptor is not null)
            {
                options.AddInterceptors(interceptor);
            }
        });
        services.AddIdentityCore<GeneratedUser>()
            .AddRoles<IdentityRole>()
            .AddEntityFrameworkStores<GeneratedTokenContext>()
            .AddMrbrGeneratedIdentityStore<GeneratedTokenContext>();
        return services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateOnBuild = true,
            ValidateScopes = true
        });
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
        SearchKeyHandles = CreateSearchKeyHandles(id, hashing)
    };

    private static IReadOnlyDictionary<string, ulong>? CreateSearchKeyHandles(int id, bool hashing) =>
        !hashing
            ? null
            : id == 1
                ? new Dictionary<string, ulong>
                {
                    ["IdentityUserName"] = checked((ulong)id),
                    ["IdentityEmail"] = checked((ulong)id)
                }
                : new Dictionary<string, ulong>
                {
                    ["IdentityTokenLookup"] = checked((ulong)id)
                };

    private static async Task<string> ScalarStringAsync(NpgsqlConnection connection, string sql)
    {
        await using NpgsqlCommand command = new(sql, connection);
        return (string)(await command.ExecuteScalarAsync()
            ?? throw new InvalidOperationException("PostgreSQL metadata query returned no value."));
    }

    private static void AssertProtected(string stored, string plaintext)
    {
        Assert.StartsWith("protected:", stored, StringComparison.Ordinal);
        Assert.DoesNotContain(plaintext, stored, StringComparison.Ordinal);
    }
}

[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class PostgreSqlCollection
{
    public const string Name = "PostgreSQL integration";
}

public sealed class PostgreSqlFactAttribute : FactAttribute
{
    public PostgreSqlFactAttribute()
    {
        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(PostgreSqlTestDatabase.ConnectionStringVariable)))
        {
            Skip = $"Set {PostgreSqlTestDatabase.ConnectionStringVariable} to run PostgreSQL integration tests.";
        }
    }
}

internal sealed class PostgreSqlTestDatabase : IAsyncDisposable
{
    public const string ConnectionStringVariable = "MRBR_TEST_POSTGRES_CONNECTION_STRING";

    private readonly string _adminConnectionString;
    private readonly string _databaseName;

    private PostgreSqlTestDatabase(string adminConnectionString, string databaseName, string connectionString)
    {
        _adminConnectionString = adminConnectionString;
        _databaseName = databaseName;
        ConnectionString = connectionString;
    }

    public string ConnectionString { get; }

    public static async Task<PostgreSqlTestDatabase> CreateAsync()
    {
        string baseConnectionString = Environment.GetEnvironmentVariable(ConnectionStringVariable)
            ?? throw new InvalidOperationException($"{ConnectionStringVariable} is required.");
        var adminBuilder = new NpgsqlConnectionStringBuilder(baseConnectionString)
        {
            Database = "postgres",
            Pooling = false
        };
        string databaseName = "mrbr_identity_" + Guid.NewGuid().ToString("N");
        await using (NpgsqlConnection admin = new(adminBuilder.ConnectionString))
        {
            await admin.OpenAsync();
            await using NpgsqlCommand create = new($"CREATE DATABASE \"{databaseName}\"", admin);
            await create.ExecuteNonQueryAsync();
        }

        var testBuilder = new NpgsqlConnectionStringBuilder(baseConnectionString)
        {
            Database = databaseName,
            Pooling = false
        };
        return new PostgreSqlTestDatabase(adminBuilder.ConnectionString, databaseName, testBuilder.ConnectionString);
    }

    public async ValueTask DisposeAsync()
    {
        await using NpgsqlConnection admin = new(_adminConnectionString);
        await admin.OpenAsync();
        await using NpgsqlCommand drop = new($"DROP DATABASE IF EXISTS \"{_databaseName}\" WITH (FORCE)", admin);
        await drop.ExecuteNonQueryAsync();
    }
}

internal sealed class TokenRouteBarrierInterceptor(Barrier barrier) : DbCommandInterceptor
{
    private int _routeQueryCount;

    public override async ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(
        DbCommand command,
        CommandEventData eventData,
        InterceptionResult<DbDataReader> result,
        CancellationToken cancellationToken = default)
    {
        if (command.CommandText.Contains("AspNetUserTokens", StringComparison.Ordinal) &&
            command.CommandText.Contains("RoutingHash", StringComparison.Ordinal) &&
            Interlocked.Increment(ref _routeQueryCount) <= 2)
        {
            bool synchronized = await Task.Run(
                () => barrier.SignalAndWait(TimeSpan.FromSeconds(15), cancellationToken),
                cancellationToken);
            if (!synchronized)
            {
                throw new TimeoutException("Concurrent PostgreSQL token queries did not reach the barrier.");
            }
        }

        return await base.ReaderExecutingAsync(command, eventData, result, cancellationToken);
    }
}
