using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Engines;
using BenchmarkDotNet.Order;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Mrbr.Encryption.Data.Common.Algorithms;
using Mrbr.Encryption.Data.Common.Attributes;
using Mrbr.Encryption.Data.EntityFramework.Extensions;
using Mrbr.Encryption.Data.EntityFramework.Services;
using Mrbr.Encryption.Data.Generated;
using Mrbr.Encryption.Data.GeneratedIdentity;
using Mrbr.Service.EncryptionManager.Extensions;
using Mrbr.Service.KeyManager.Configuration;
using Mrbr.Service.KeyManager.Services;
using System.Security.Cryptography;

namespace Mrbr.Encryption.Data.Identity.Benchmarks;

public enum IdentityProtectionProfile { Plain, Aes256, MlKem768 }
public enum IdentityLoadWorkload { CreateUsers, LookupUsers }

[MemoryDiagnoser]
[SimpleJob(RunStrategy.ColdStart, launchCount: 1, warmupCount: 1, iterationCount: 3, invocationCount: 1)]
[Orderer(SummaryOrderPolicy.FastestToSlowest)]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByParams)]
public class IdentityUserLoadBenchmarks {
    private IdentityBenchmarkHost? _host;

    [Params(IdentityProtectionProfile.Plain, IdentityProtectionProfile.Aes256, IdentityProtectionProfile.MlKem768)]
    public IdentityProtectionProfile Profile { get; set; }

    [Params(1, 100, 1_000)]
    public int UserCount { get; set; }

    [Params(IdentityLoadWorkload.CreateUsers, IdentityLoadWorkload.LookupUsers)]
    public IdentityLoadWorkload Workload { get; set; }

    [IterationSetup]
    public void Setup() {
        _host = IdentityBenchmarkHost.Create(Profile);
        if (Workload == IdentityLoadWorkload.LookupUsers)
            _host.CreateUsersAsync(UserCount).GetAwaiter().GetResult();
    }

    [IterationCleanup]
    public void Cleanup() {
        _host?.Dispose();
        _host = null;
    }

    [Benchmark(OperationsPerInvoke = 1)]
    [InvocationCount(1)]
    public Task Execute() => Workload switch {
        IdentityLoadWorkload.CreateUsers => _host!.CreateUsersAsync(UserCount),
        IdentityLoadWorkload.LookupUsers => _host!.LookupUsersAsync(UserCount),
        _ => throw new InvalidOperationException()
    };
}

internal sealed class IdentityBenchmarkHost : IDisposable {
    private readonly SqliteConnection _connection;
    private readonly ServiceProvider _provider;
    private readonly IKeyService? _keyService;
    private readonly IdentityProtectionProfile _profile;

    private IdentityBenchmarkHost(SqliteConnection connection, ServiceProvider provider, IKeyService? keyService, IdentityProtectionProfile profile) {
        _connection = connection;
        _provider = provider;
        _keyService = keyService;
        _profile = profile;
    }

    public static IdentityBenchmarkHost Create(IdentityProtectionProfile profile) {
        var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
        var services = new ServiceCollection();
        services.AddLogging();
        IKeyService? keyService = null;

        if (profile == IdentityProtectionProfile.Plain) {
            services.AddSingleton(connection);
            services.AddDbContext<PlainIdentityBenchmarkContext>(options => options.UseSqlite(connection));
            services.AddIdentityCore<IdentityUser>().AddRoles<IdentityRole>().AddEntityFrameworkStores<PlainIdentityBenchmarkContext>();
        }
        else {
            const byte piiId = 1, lookupId = 2, credentialId = 4, operationalId = 7;
            KeyServiceConfig keyConfig = new()
            {
                CreateEntry(piiId, 0), CreateEntry(lookupId, 17), CreateEntry(credentialId, 37), CreateEntry(operationalId, 61)
            };
            keyService = new KeyService(new KeyServiceOptions(Options.Create(keyConfig)));
            ulong userNameHandle = ProvisionSearchKey(keyService, lookupId);
            ulong emailHandle = ProvisionSearchKey(keyService, lookupId);
            ulong roleHandle = ProvisionSearchKey(keyService, lookupId);
            DataEncryptionAlgorithm algorithm = profile == IdentityProtectionProfile.Aes256
                ? DataEncryptionAlgorithm.Aes256 : DataEncryptionAlgorithm.MlKem768;
            var map = new SourceKeyMapConfig {
                IdentityPII = Encryption(piiId, algorithm),
                IdentityLookup = new SourceKeyConfig {
                    SourceKeyId = lookupId,
                    HashAlgorithm = DataHashAlgorithm.HmacSha256,
                    SearchKeyHandles = new Dictionary<string, ulong> {
                        ["IdentityUserName"] = userNameHandle,
                        ["IdentityEmail"] = emailHandle,
                        ["IdentityRoleName"] = roleHandle
                    }
                },
                IdentityCredential = Encryption(credentialId, algorithm),
                IdentityOperational = Encryption(operationalId, algorithm)
            };
            services.AddSingleton(keyService);
            services.AddSingleton<IKeyService>(keyService);
            services.AddEncryptionManager();
            services.AddMrbrEntityEncryption();
            services.AddSingleton(map);
            if (profile == IdentityProtectionProfile.Aes256) {
                services.AddDbContext<AesIdentityBenchmarkContext>((sp, options) => options.UseSqlite(connection).AddMrbrEntityEncryption(sp));
                services.AddIdentityCore<AesBenchmarkUser>().AddRoles<AesBenchmarkRole>()
                    .AddEntityFrameworkStores<AesIdentityBenchmarkContext>().AddMrbrGeneratedIdentityStore<AesIdentityBenchmarkContext>();
            }
            else {
                services.AddDbContext<PqcIdentityBenchmarkContext>((sp, options) => options.UseSqlite(connection).AddMrbrEntityEncryption(sp));
                services.AddIdentityCore<PqcBenchmarkUser>().AddRoles<PqcBenchmarkRole>()
                    .AddEntityFrameworkStores<PqcIdentityBenchmarkContext>().AddMrbrGeneratedIdentityStore<PqcIdentityBenchmarkContext>();
            }
        }

        ServiceProvider provider = services.BuildServiceProvider();
        using IServiceScope scope = provider.CreateScope();
        if (profile == IdentityProtectionProfile.Plain)
            scope.ServiceProvider.GetRequiredService<PlainIdentityBenchmarkContext>().Database.EnsureCreated();
        else if (profile == IdentityProtectionProfile.Aes256)
            scope.ServiceProvider.GetRequiredService<AesIdentityBenchmarkContext>().Database.EnsureCreated();
        else
            scope.ServiceProvider.GetRequiredService<PqcIdentityBenchmarkContext>().Database.EnsureCreated();
        return new IdentityBenchmarkHost(connection, provider, keyService, profile);
    }

    public async Task CreateUsersAsync(int count) {
        using IServiceScope scope = _provider.CreateScope();
        if (_profile == IdentityProtectionProfile.Plain) {
            UserManager<IdentityUser> manager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
            for (int i = 0; i < count; i++) Ensure(await manager.CreateAsync(new IdentityUser(UserName(i)) { Email = Email(i), PhoneNumber = Phone(i) }));
        }
        else {
            if (_profile == IdentityProtectionProfile.Aes256) {
                UserManager<AesBenchmarkUser> manager = scope.ServiceProvider.GetRequiredService<UserManager<AesBenchmarkUser>>();
                for (int i = 0; i < count; i++) Ensure(await manager.CreateAsync(new AesBenchmarkUser { UserName = UserName(i), Email = Email(i), PhoneNumber = Phone(i) }));
            }
            else {
                UserManager<PqcBenchmarkUser> manager = scope.ServiceProvider.GetRequiredService<UserManager<PqcBenchmarkUser>>();
                for (int i = 0; i < count; i++) Ensure(await manager.CreateAsync(new PqcBenchmarkUser { UserName = UserName(i), Email = Email(i), PhoneNumber = Phone(i) }));
            }
        }
    }

    public async Task LookupUsersAsync(int count) {
        using IServiceScope scope = _provider.CreateScope();
        if (_profile == IdentityProtectionProfile.Plain) {
            UserManager<IdentityUser> manager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
            for (int i = 0; i < count; i++)
                if (await manager.FindByNameAsync(UserName(i)) is null || await manager.FindByEmailAsync(Email(i)) is null) throw new InvalidOperationException("Plain lookup failed.");
        }
        else {
            if (_profile == IdentityProtectionProfile.Aes256) {
                UserManager<AesBenchmarkUser> manager = scope.ServiceProvider.GetRequiredService<UserManager<AesBenchmarkUser>>();
                for (int i = 0; i < count; i++)
                    if (await manager.FindByNameAsync(UserName(i)) is null) throw new InvalidOperationException($"AES username lookup failed at {i}.");
                    else if (await manager.FindByEmailAsync(Email(i)) is null) throw new InvalidOperationException($"AES email lookup failed at {i}.");
            }
            else {
                UserManager<PqcBenchmarkUser> manager = scope.ServiceProvider.GetRequiredService<UserManager<PqcBenchmarkUser>>();
                for (int i = 0; i < count; i++)
                    if (await manager.FindByNameAsync(UserName(i)) is null) throw new InvalidOperationException($"PQC username lookup failed at {i}.");
                    else if (await manager.FindByEmailAsync(Email(i)) is null) throw new InvalidOperationException($"PQC email lookup failed at {i}.");
            }
        }
    }

    public void Dispose() { _provider.Dispose(); _connection.Dispose(); (_keyService as IDisposable)?.Dispose(); }
    private static string UserName(int i) => $"benchmark-user-{i:D5}";
    private static string Email(int i) => $"benchmark-user-{i:D5}@example.test";
    private static string Phone(int i) => $"+44 7700 {i % 1_000_000:D6}";
    private static void Ensure(IdentityResult result) { if (!result.Succeeded) throw new InvalidOperationException(string.Join("; ", result.Errors.Select(e => e.Description))); }
    private static SourceKeyConfig Encryption(byte id, DataEncryptionAlgorithm algorithm) => new() { SourceKeyId = id, EncryptionAlgorithm = algorithm };
    private static ulong ProvisionSearchKey(IKeyService service, byte id) { byte[] key = service.GenerateKey256(id, out ulong handle); CryptographicOperations.ZeroMemory(key); return handle; }
    private static KeyServiceEntry CreateEntry(byte id, int offset) => new() {
        KeySourceId = id,
        Type = KeyType.Block,
        Value = string.Create(4096, offset, static (span, start) => { for (int i = 0; i < span.Length; i++) span[i] = (char)('!' + ((i + start) % 90)); }),
        KeyHandleMask = "565342976",
        BlockSettings = new KeyBlockSettings { MinLength = 64, MaxLength = 128 }
    };
}

internal sealed class PlainIdentityBenchmarkContext(DbContextOptions<PlainIdentityBenchmarkContext> options)
    : IdentityDbContext<IdentityUser, IdentityRole, string>(options);

internal sealed class AesBenchmarkUser : EncryptedIdentityUser {
    [Encrypted("IdentityPII")] public override string? UserName { get; set; }
    [Encrypted("IdentityPII")]
    [Hashed("IdentityLookup", "IdentityUserName", HashIndexType.Unique, DataNormalization.None)]
    public override string? NormalizedUserName { get; set; }
    [Encrypted("IdentityPII")]
    [Hashed("IdentityLookup", "IdentityEmail", HashIndexType.NonUnique, DataNormalization.None)]
    public override string? NormalizedEmail { get; set; }
    [Encrypted("IdentityPII")] public override string? Email { get; set; }
    [Encrypted("IdentityPII")] public override string? PhoneNumber { get; set; }
    [Encrypted("IdentityCredential")] public override string? SecurityStamp { get; set; }
    [Encrypted("IdentityOperational")] public override bool EmailConfirmed { get; set; }
    [Encrypted("IdentityOperational")] public override bool PhoneNumberConfirmed { get; set; }
    [Encrypted("IdentityOperational")] public override bool TwoFactorEnabled { get; set; }
    [Encrypted("IdentityOperational")] public override DateTimeOffset? LockoutEnd { get; set; }
    [Encrypted("IdentityOperational")] public override bool LockoutEnabled { get; set; }
    [Encrypted("IdentityOperational")] public override int AccessFailedCount { get; set; }
}
internal sealed class AesBenchmarkRole : EncryptedIdentityRole;
internal sealed class PqcBenchmarkUser : EncryptedIdentityUser {
    [Encrypted("IdentityPII")] public override string? UserName { get; set; }
    [Encrypted("IdentityPII")]
    [Hashed("IdentityLookup", "IdentityUserName", HashIndexType.Unique, DataNormalization.None)]
    public override string? NormalizedUserName { get; set; }
    [Encrypted("IdentityPII")]
    [Hashed("IdentityLookup", "IdentityEmail", HashIndexType.NonUnique, DataNormalization.None)]
    public override string? NormalizedEmail { get; set; }
    [Encrypted("IdentityPII")] public override string? Email { get; set; }
    [Encrypted("IdentityPII")] public override string? PhoneNumber { get; set; }
    [Encrypted("IdentityCredential")] public override string? SecurityStamp { get; set; }
    [Encrypted("IdentityOperational")] public override bool EmailConfirmed { get; set; }
    [Encrypted("IdentityOperational")] public override bool PhoneNumberConfirmed { get; set; }
    [Encrypted("IdentityOperational")] public override bool TwoFactorEnabled { get; set; }
    [Encrypted("IdentityOperational")] public override DateTimeOffset? LockoutEnd { get; set; }
    [Encrypted("IdentityOperational")] public override bool LockoutEnabled { get; set; }
    [Encrypted("IdentityOperational")] public override int AccessFailedCount { get; set; }
}
internal sealed class PqcBenchmarkRole : EncryptedIdentityRole;

[GenerateEncryptedIdentityLookup]
internal sealed class AesIdentityBenchmarkContext(DbContextOptions<AesIdentityBenchmarkContext> options, IEntityDataProtectionService protection, SourceKeyMapConfig map)
    : IdentityDbContext<AesBenchmarkUser, AesBenchmarkRole, string>(options) {
    protected override void OnModelCreating(ModelBuilder modelBuilder) { base.OnModelCreating(modelBuilder); ConfigureProtectedIdentity(modelBuilder, protection, map); }
    internal static void ConfigureProtectedIdentity(ModelBuilder modelBuilder, IEntityDataProtectionService protection, SourceKeyMapConfig map) {
        modelBuilder.RemoveIdentityPlaintextLookupIndexes<AesBenchmarkUser>();
        modelBuilder.RemoveIdentityPlaintextRoleLookupIndex<AesBenchmarkRole>();
        modelBuilder.AddMrbrGeneratedEncryption(protection, map);
    }
}

[GenerateEncryptedIdentityLookup]
internal sealed class PqcIdentityBenchmarkContext(DbContextOptions<PqcIdentityBenchmarkContext> options, IEntityDataProtectionService protection, SourceKeyMapConfig map)
    : IdentityDbContext<PqcBenchmarkUser, PqcBenchmarkRole, string>(options) {
    protected override void OnModelCreating(ModelBuilder modelBuilder) {
        base.OnModelCreating(modelBuilder);
        modelBuilder.RemoveIdentityPlaintextLookupIndexes<PqcBenchmarkUser>();
        modelBuilder.RemoveIdentityPlaintextRoleLookupIndex<PqcBenchmarkRole>();
        modelBuilder.AddMrbrGeneratedEncryption(protection, map);
    }
}
