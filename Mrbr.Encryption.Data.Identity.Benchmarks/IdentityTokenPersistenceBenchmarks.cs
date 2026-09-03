using BenchmarkDotNet.Attributes;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Mrbr.Encryption.Data.Common.Results;
using Mrbr.Encryption.Data.EntityFramework.Metadata;
using Npgsql;
using System.Data.Common;

namespace Mrbr.Encryption.Data.Identity.Benchmarks;

[MemoryDiagnoser]
public class IdentityTokenPersistenceBenchmarks
{
    private const string RouteDomain = "Mrbr.Encryption.Data.Identity/UserTokenRoute";
    private readonly string[] _providers = PostgreSqlBenchmarkDatabase.IsConfigured
        ? ["SQLite", "PostgreSQL"]
        : ["SQLite"];
    private BenchmarkProtectionFixture _fixture = null!;
    private DbConnection? _keepAliveConnection;
    private BenchmarkTokenContext _context = null!;
    private PostgreSqlBenchmarkDatabase? _postgresDatabase;
    private long _sequence;

    public IEnumerable<string> Providers => _providers;

    [ParamsSource(nameof(Providers))]
    public string Provider { get; set; } = null!;

    [GlobalSetup]
    public async Task Setup()
    {
        _fixture = new BenchmarkProtectionFixture();
        DbContextOptions<BenchmarkTokenContext> options;
        if (Provider == "PostgreSQL")
        {
            _postgresDatabase = await PostgreSqlBenchmarkDatabase.CreateAsync();
            var builder = new NpgsqlConnectionStringBuilder(_postgresDatabase.ConnectionString) { Pooling = true };
            options = new DbContextOptionsBuilder<BenchmarkTokenContext>()
                .UseNpgsql(builder.ConnectionString)
                .Options;
        }
        else
        {
            var sqlite = new SqliteConnection("Data Source=:memory:");
            await sqlite.OpenAsync();
            _keepAliveConnection = sqlite;
            options = new DbContextOptionsBuilder<BenchmarkTokenContext>()
                .UseSqlite(sqlite)
                .Options;
        }

        _context = new BenchmarkTokenContext(options, _fixture);
        await _context.Database.EnsureCreatedAsync();
    }

    [GlobalCleanup]
    public async Task Cleanup()
    {
        await _context.DisposeAsync();
        if (_keepAliveConnection is not null)
        {
            await _keepAliveConnection.DisposeAsync();
        }
        if (_postgresDatabase is not null)
        {
            await _postgresDatabase.DisposeAsync();
        }
        _fixture.Dispose();
    }

    [Benchmark(Baseline = true)]
    public Task<int> PlainInsertLookupDelete() => RunCycleAsync(protectedData: false);

    [Benchmark]
    public Task<int> ProtectedInsertLookupDelete() => RunCycleAsync(protectedData: true);

    private async Task<int> RunCycleAsync(bool protectedData)
    {
        string name = "benchmark-" + Interlocked.Increment(ref _sequence).ToString(System.Globalization.CultureInfo.InvariantCulture);
        string[] route = ["benchmark-user", "ExampleProvider", name];
        ProtectionResult<string> hashResult = _fixture.Service.ComputeCompositeSearchHash(
            RouteDomain,
            route,
            _fixture.RouteHashConfiguration);
        string hash = hashResult.Value;

        if (protectedData)
        {
            var token = new ProtectedBenchmarkToken
            {
                TokenId = Guid.CreateVersion7(),
                UserId = route[0],
                LoginProvider = route[1],
                Name = route[2],
                Value = "benchmark-token-secret",
                RoutingHash = hash
            };
            _context.ProtectedTokens.Add(token);
            await _context.SaveChangesAsync();
            _context.Entry(token).State = EntityState.Detached;
            ProtectedBenchmarkToken found = await _context.ProtectedTokens.AsNoTracking()
                .SingleAsync(value => value.RoutingHash == hash);
            await _context.ProtectedTokens.Where(value => value.TokenId == found.TokenId).ExecuteDeleteAsync();
            return found.Value.Length;
        }

        var plain = new PlainBenchmarkToken
        {
            TokenId = Guid.CreateVersion7(),
            UserId = route[0],
            LoginProvider = route[1],
            Name = route[2],
            Value = "benchmark-token-secret",
            RoutingHash = hash
        };
        _context.PlainTokens.Add(plain);
        await _context.SaveChangesAsync();
        _context.Entry(plain).State = EntityState.Detached;
        PlainBenchmarkToken plainFound = await _context.PlainTokens.AsNoTracking()
            .SingleAsync(value => value.RoutingHash == hash);
        await _context.PlainTokens.Where(value => value.TokenId == plainFound.TokenId).ExecuteDeleteAsync();
        return plainFound.Value.Length;
    }
}

internal sealed class BenchmarkTokenContext(
    DbContextOptions<BenchmarkTokenContext> options,
    BenchmarkProtectionFixture fixture) : DbContext(options)
{
    public DbSet<ProtectedBenchmarkToken> ProtectedTokens => Set<ProtectedBenchmarkToken>();

    public DbSet<PlainBenchmarkToken> PlainTokens => Set<PlainBenchmarkToken>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        ConfigureProtectedToken(modelBuilder.Entity<ProtectedBenchmarkToken>());
        ConfigurePlainToken(modelBuilder.Entity<PlainBenchmarkToken>());
        var generated = new GeneratedEncryptionModelBuilder(modelBuilder, fixture.Service);
        generated.EncryptedString<ProtectedBenchmarkToken>(nameof(ProtectedBenchmarkToken.LoginProvider), fixture.TokenEncryptionConfiguration);
        generated.EncryptedString<ProtectedBenchmarkToken>(nameof(ProtectedBenchmarkToken.Name), fixture.NameEncryptionConfiguration);
        generated.EncryptedString<ProtectedBenchmarkToken>(nameof(ProtectedBenchmarkToken.Value), fixture.ValueEncryptionConfiguration);
    }

    private static void ConfigureProtectedToken(Microsoft.EntityFrameworkCore.Metadata.Builders.EntityTypeBuilder<ProtectedBenchmarkToken> token)
    {
        token.ToTable("ProtectedTokens");
        token.HasKey(value => value.TokenId);
        token.Property(value => value.TokenId).ValueGeneratedNever();
        token.Property(value => value.RoutingHash).HasMaxLength(128).IsRequired();
        token.HasIndex(value => value.RoutingHash).IsUnique();
    }

    private static void ConfigurePlainToken(Microsoft.EntityFrameworkCore.Metadata.Builders.EntityTypeBuilder<PlainBenchmarkToken> token)
    {
        token.ToTable("PlainTokens");
        token.HasKey(value => value.TokenId);
        token.Property(value => value.TokenId).ValueGeneratedNever();
        token.Property(value => value.RoutingHash).HasMaxLength(128).IsRequired();
        token.HasIndex(value => value.RoutingHash).IsUnique();
    }
}

internal sealed class ProtectedBenchmarkToken
{
    public Guid TokenId { get; set; }
    public string UserId { get; set; } = null!;
    public string LoginProvider { get; set; } = null!;
    public string Name { get; set; } = null!;
    public string Value { get; set; } = null!;
    public string RoutingHash { get; set; } = null!;
}

internal sealed class PlainBenchmarkToken
{
    public Guid TokenId { get; set; }
    public string UserId { get; set; } = null!;
    public string LoginProvider { get; set; } = null!;
    public string Name { get; set; } = null!;
    public string Value { get; set; } = null!;
    public string RoutingHash { get; set; } = null!;
}

internal sealed class PostgreSqlBenchmarkDatabase : IAsyncDisposable
{
    public const string ConnectionStringVariable = "MRBR_TEST_POSTGRES_CONNECTION_STRING";
    private readonly string _adminConnectionString;
    private readonly string _databaseName;

    private PostgreSqlBenchmarkDatabase(string adminConnectionString, string databaseName, string connectionString)
    {
        _adminConnectionString = adminConnectionString;
        _databaseName = databaseName;
        ConnectionString = connectionString;
    }

    public static bool IsConfigured =>
        !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(ConnectionStringVariable));

    public string ConnectionString { get; }

    public static async Task<PostgreSqlBenchmarkDatabase> CreateAsync()
    {
        string baseConnectionString = Environment.GetEnvironmentVariable(ConnectionStringVariable)
            ?? throw new InvalidOperationException($"{ConnectionStringVariable} is required for PostgreSQL benchmarks.");
        var adminBuilder = new NpgsqlConnectionStringBuilder(baseConnectionString)
        {
            Database = "postgres",
            Pooling = false
        };
        string databaseName = "mrbr_benchmark_" + Guid.NewGuid().ToString("N");
        await using (NpgsqlConnection admin = new(adminBuilder.ConnectionString))
        {
            await admin.OpenAsync();
            await using NpgsqlCommand create = new($"CREATE DATABASE \"{databaseName}\"", admin);
            await create.ExecuteNonQueryAsync();
        }

        var testBuilder = new NpgsqlConnectionStringBuilder(baseConnectionString)
        {
            Database = databaseName
        };
        return new PostgreSqlBenchmarkDatabase(adminBuilder.ConnectionString, databaseName, testBuilder.ConnectionString);
    }

    public async ValueTask DisposeAsync()
    {
        NpgsqlConnection.ClearAllPools();
        await using NpgsqlConnection admin = new(_adminConnectionString);
        await admin.OpenAsync();
        await using NpgsqlCommand drop = new($"DROP DATABASE IF EXISTS \"{_databaseName}\" WITH (FORCE)", admin);
        await drop.ExecuteNonQueryAsync();
    }
}
