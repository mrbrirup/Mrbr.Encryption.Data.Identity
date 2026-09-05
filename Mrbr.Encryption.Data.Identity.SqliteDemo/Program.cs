using System.Data.Common;
using System.Security.Cryptography;
using System.Security.Claims;
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
using Mrbr.Encryption.Data.Identity;
using Mrbr.Service.EncryptionManager.Extensions;
using Mrbr.Service.KeyManager.Configuration;
using Mrbr.Service.KeyManager.Services;

const byte piiSourceKeyId = 1;
const byte lookupSourceKeyId = 2;
const byte authorizationSourceKeyId = 3;
const byte credentialSourceKeyId = 4;
const byte externalLoginSourceKeyId = 5;
const byte passkeySourceKeyId = 6;
const byte operationalSourceKeyId = 7;
const byte tokenSourceKeyId = 8;
#if PQC_SHOWCASE
const DataEncryptionAlgorithm showcaseEncryptionAlgorithm = DataEncryptionAlgorithm.MlKem768;
const string showcaseDatabasePrefix = "identity-pqc-encryption-showcase";
#else
const DataEncryptionAlgorithm showcaseEncryptionAlgorithm = DataEncryptionAlgorithm.Aes256;
const string showcaseDatabasePrefix = "identity-encryption-showcase";
#endif
const string userName = "alice";
const string email = "alice@example.test";
const string phoneNumber = "+44 7700 900123";

if (args.Length > 1)
{
    throw new ArgumentException("Usage: dotnet run -- [database-path]");
}
string databasePath = args.Length == 1
    ? Path.GetFullPath(args[0])
    : Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..",
        $"{showcaseDatabasePrefix}-{DateTime.UtcNow:yyyyMMdd-HHmmss}.db"));
if (File.Exists(databasePath))
{
    throw new InvalidOperationException($"The showcase database already exists: {databasePath}. Choose a new path; existing databases are never overwritten.");
}

KeyServiceConfig keyConfig = new()
{
    CreateKeySourceEntry(piiSourceKeyId, 0),
    CreateKeySourceEntry(lookupSourceKeyId, 11),
    CreateKeySourceEntry(authorizationSourceKeyId, 23),
    CreateKeySourceEntry(credentialSourceKeyId, 37),
    CreateKeySourceEntry(externalLoginSourceKeyId, 51),
    CreateKeySourceEntry(passkeySourceKeyId, 67),
    CreateKeySourceEntry(operationalSourceKeyId, 79)
    , CreateKeySourceEntry(tokenSourceKeyId, 89)
};

KeyService keyService = new(new KeyServiceOptions(Options.Create(keyConfig)));
byte[] userNameSearchKey = keyService.GenerateKey256(lookupSourceKeyId, out ulong userNameSearchKeyHandle);
byte[] emailSearchKey = keyService.GenerateKey256(lookupSourceKeyId, out ulong emailSearchKeyHandle);
byte[] roleNameSearchKey = keyService.GenerateKey256(lookupSourceKeyId, out ulong roleNameSearchKeyHandle);
byte[] claimSearchKey = keyService.GenerateKey256(lookupSourceKeyId, out ulong claimSearchKeyHandle);
byte[] loginSearchKey = keyService.GenerateKey256(lookupSourceKeyId, out ulong loginSearchKeyHandle);
byte[] passkeySearchKey = keyService.GenerateKey256(lookupSourceKeyId, out ulong passkeySearchKeyHandle);
byte[] tokenSearchKey = keyService.GenerateKey256(lookupSourceKeyId, out ulong tokenSearchKeyHandle);
CryptographicOperations.ZeroMemory(userNameSearchKey);
CryptographicOperations.ZeroMemory(emailSearchKey);
CryptographicOperations.ZeroMemory(roleNameSearchKey);
CryptographicOperations.ZeroMemory(claimSearchKey);
CryptographicOperations.ZeroMemory(loginSearchKey);
CryptographicOperations.ZeroMemory(passkeySearchKey);
CryptographicOperations.ZeroMemory(tokenSearchKey);

ServiceCollection services = new();
services.AddLogging();
services.AddSingleton<IKeyService>(keyService);
services.AddEncryptionManager();
services.AddMrbrEntityEncryption();
services.AddSingleton(new SourceKeyMapConfig
{
    IdentityPII = new SourceKeyConfig
    {
        SourceKeyId = piiSourceKeyId,
        EncryptionAlgorithm = showcaseEncryptionAlgorithm
    },
    IdentityLookup = new SourceKeyConfig
    {
        SourceKeyId = lookupSourceKeyId,
        HashAlgorithm = DataHashAlgorithm.HmacSha256,
        SearchKeyHandles = new Dictionary<string, ulong>
        {
            ["IdentityUserName"] = userNameSearchKeyHandle,
            ["IdentityEmail"] = emailSearchKeyHandle,
            ["IdentityRoleName"] = roleNameSearchKeyHandle
            , ["IdentityClaimRoute"] = claimSearchKeyHandle,
            ["IdentityLoginRoute"] = loginSearchKeyHandle,
            ["IdentityPasskeyCredential"] = passkeySearchKeyHandle
            , ["IdentityTokenLookup"] = tokenSearchKeyHandle
        }
    },
    IdentityAuthorization = new SourceKeyConfig
    {
        SourceKeyId = authorizationSourceKeyId,
        EncryptionAlgorithm = showcaseEncryptionAlgorithm
    },
    IdentityCredential = new SourceKeyConfig
    {
        SourceKeyId = credentialSourceKeyId,
        EncryptionAlgorithm = showcaseEncryptionAlgorithm
    },
    IdentityExternalLogin = new SourceKeyConfig
    {
        SourceKeyId = externalLoginSourceKeyId,
        EncryptionAlgorithm = showcaseEncryptionAlgorithm
    },
    IdentityPasskey = new SourceKeyConfig
    {
        SourceKeyId = passkeySourceKeyId,
        EncryptionAlgorithm = showcaseEncryptionAlgorithm
    },
    IdentityOperational = new SourceKeyConfig
    {
        SourceKeyId = operationalSourceKeyId,
        EncryptionAlgorithm = showcaseEncryptionAlgorithm
    },
    IdentityToken = new SourceKeyConfig
    {
        SourceKeyId = tokenSourceKeyId,
        EncryptionAlgorithm = showcaseEncryptionAlgorithm
    },
    IdentityTokenLookup = new SourceKeyConfig
    {
        SourceKeyId = lookupSourceKeyId,
        HashAlgorithm = DataHashAlgorithm.HmacSha256,
        SearchKeyHandles = new Dictionary<string, ulong> { ["IdentityTokenLookup"] = tokenSearchKeyHandle }
    }
});
services.AddDbContext<DemoIdentityDbContext>((serviceProvider, options) =>
    options
        .UseSqlite($"Data Source={databasePath};Pooling=False")
        .AddMrbrEntityEncryption(serviceProvider));
services
    .AddIdentityCore<EncryptedIdentityUser>(options => options.User.RequireUniqueEmail = false)
    .AddRoles<EncryptedIdentityRole>()
    .AddEntityFrameworkStores<DemoIdentityDbContext>()
    .AddMrbrGeneratedIdentityStore<DemoIdentityDbContext>();

await using ServiceProvider provider = services.BuildServiceProvider();
await using AsyncServiceScope scope = provider.CreateAsyncScope();
DemoIdentityDbContext context = scope.ServiceProvider.GetRequiredService<DemoIdentityDbContext>();
await context.Database.EnsureCreatedAsync();

UserManager<EncryptedIdentityUser> users = scope.ServiceProvider.GetRequiredService<UserManager<EncryptedIdentityUser>>();
EncryptedIdentityUser user = new()
{
    UserName = userName,
    Email = email,
    PhoneNumber = phoneNumber
    , EmailConfirmed = true,
    LockoutEnabled = true,
    LockoutEnd = DateTimeOffset.UtcNow.AddMinutes(5),
    AccessFailedCount = 2
};
IdentityResult created = await users.CreateAsync(user);
if (!created.Succeeded)
{
    throw new InvalidOperationException(string.Join(Environment.NewLine, created.Errors.Select(error => error.Description)));
}

await users.SetAuthenticationTokenAsync(user, "ExampleProvider", "RefreshToken", "demo-token-secret");
if (await users.GetAuthenticationTokenAsync(user, "ExampleProvider", "RefreshToken") != "demo-token-secret")
{
    throw new InvalidOperationException("The protected Identity token round trip failed.");
}

RoleManager<EncryptedIdentityRole> roles = scope.ServiceProvider.GetRequiredService<RoleManager<EncryptedIdentityRole>>();
IdentityResult roleCreated = await roles.CreateAsync(new EncryptedIdentityRole { Name = "Administrator" });
if (!roleCreated.Succeeded)
{
    throw new InvalidOperationException(string.Join(Environment.NewLine, roleCreated.Errors.Select(error => error.Description)));
}

EncryptedIdentityRole? foundRole = await roles.FindByNameAsync("Administrator");
if (foundRole?.Name != "Administrator")
{
    throw new InvalidOperationException("The encrypted Identity role round trip did not return the expected plaintext value.");
}

Claim originalClaim = new("permission", "reports.read");
Claim replacementClaim = new("permission", "reports.manage");
IdentityResult userClaimAdded = await users.AddClaimAsync(user, originalClaim);
IdentityResult roleClaimAdded = await roles.AddClaimAsync(foundRole, originalClaim);
if (!userClaimAdded.Succeeded || !roleClaimAdded.Succeeded)
{
    throw new InvalidOperationException("The encrypted Identity claims could not be created.");
}
IdentityResult userClaimReplaced = await users.ReplaceClaimAsync(user, originalClaim, replacementClaim);
IdentityResult roleClaimRemoved = await roles.RemoveClaimAsync(foundRole, originalClaim);
if (!userClaimReplaced.Succeeded || !roleClaimRemoved.Succeeded ||
    !(await users.GetClaimsAsync(user)).Any(value => value.Type == replacementClaim.Type && value.Value == replacementClaim.Value))
{
    throw new InvalidOperationException("The encrypted Identity claim mutation round trip failed.");
}

UserLoginInfo externalLogin = new("ExampleProvider", "external-account-42", "Example account");
IdentityResult loginAdded = await users.AddLoginAsync(user, externalLogin);
EncryptedIdentityUser? foundByLogin = await users.FindByLoginAsync(externalLogin.LoginProvider, externalLogin.ProviderKey);
if (!loginAdded.Succeeded || foundByLogin?.Id != user.Id)
{
    throw new InvalidOperationException("The protected external-login round trip failed.");
}

byte[] credentialId = [11, 22, 33, 44, 55, 66];
UserPasskeyInfo passkey = new(
    credentialId,
    [91, 92, 93, 94],
    DateTimeOffset.UtcNow,
    7,
    ["internal", "hybrid"],
    true,
    true,
    false,
    [81, 82, 83],
    [71, 72, 73]) { Name = "Demo passkey" };
IdentityResult passkeyAdded = await users.AddOrUpdatePasskeyAsync(user, passkey);
EncryptedIdentityUser? foundByPasskey = await users.FindByPasskeyIdAsync(credentialId);
UserPasskeyInfo? loadedPasskey = await users.GetPasskeyAsync(user, credentialId);
if (!passkeyAdded.Succeeded || foundByPasskey?.Id != user.Id || loadedPasskey?.Name != passkey.Name)
{
    throw new InvalidOperationException("The protected passkey round trip failed.");
}

context.ChangeTracker.Clear();
EncryptedIdentityUser? foundByName = await users.FindByNameAsync(userName);
EncryptedIdentityUser? foundByEmail = await users.FindByEmailAsync(email);
if (foundByName?.Email != email || foundByEmail?.PhoneNumber != phoneNumber ||
    !foundByName.EmailConfirmed || !foundByName.LockoutEnabled || foundByName.AccessFailedCount != 2 || foundByName.LockoutEnd is null)
{
    throw new InvalidOperationException("The encrypted Identity round trip did not return the expected plaintext values.");
}

Console.WriteLine($"SQLite database: {databasePath}");
Console.WriteLine($"Data encryption profile: {showcaseEncryptionAlgorithm}");
Console.WriteLine($"UserManager lookup returned: {foundByName.UserName}, {foundByName.Email}, {foundByName.PhoneNumber}");
Console.WriteLine($"RoleManager lookup returned: {foundRole.Name}");
Console.WriteLine("User/role claim add, replace, and remove completed through protected routing.");
Console.WriteLine("External-login add and lookup completed through protected routing.");
Console.WriteLine("Passkey add, lookup, and materialization completed through protected routing.");
Console.WriteLine("Authentication-token add and lookup completed through protected routing.");
Console.WriteLine();
Console.WriteLine("Raw AspNetUsers values:");

await using SqliteConnection rawConnection = new($"Data Source={databasePath};Mode=ReadOnly;Pooling=False");
await rawConnection.OpenAsync();
await using DbCommand command = rawConnection.CreateCommand();
command.CommandText =
    "SELECT UserName, NormalizedUserName, NormalizedUserNameHash, " +
    "Email, NormalizedEmail, NormalizedEmailHash, PhoneNumber, EmailConfirmed, LockoutEnabled, LockoutEnd, AccessFailedCount FROM AspNetUsers";
await using DbDataReader reader = await command.ExecuteReaderAsync();
if (await reader.ReadAsync())
{
    for (int index = 0; index < reader.FieldCount; index++)
    {
        Console.WriteLine($"  {reader.GetName(index)} = {reader.GetValue(index)}");
    }
}
await reader.CloseAsync();

Console.WriteLine();
Console.WriteLine("Raw AspNetRoles values:");
await using DbCommand roleCommand = rawConnection.CreateCommand();
roleCommand.CommandText = "SELECT Name, NormalizedName, NormalizedNameHash FROM AspNetRoles";
await using DbDataReader roleReader = await roleCommand.ExecuteReaderAsync();
if (await roleReader.ReadAsync())
{
    for (int index = 0; index < roleReader.FieldCount; index++)
    {
        Console.WriteLine($"  {roleReader.GetName(index)} = {roleReader.GetValue(index)}");
    }
}
await roleReader.CloseAsync();

Console.WriteLine();
Console.WriteLine("Raw AspNetUserClaims values:");
await using DbCommand claimCommand = rawConnection.CreateCommand();
claimCommand.CommandText = "SELECT ClaimType, ClaimValue, RoutingHash FROM AspNetUserClaims";
await using DbDataReader claimReader = await claimCommand.ExecuteReaderAsync();
while (await claimReader.ReadAsync())
{
    for (int index = 0; index < claimReader.FieldCount; index++)
    {
        Console.WriteLine($"  {claimReader.GetName(index)} = {claimReader.GetValue(index)}");
    }
}
await claimReader.CloseAsync();

Console.WriteLine();
Console.WriteLine("Raw AspNetUserTokens values:");
await using DbCommand tokenCommand = rawConnection.CreateCommand();
tokenCommand.CommandText = "SELECT TokenId, LoginProvider, Name, Value, RoutingHash, UserId FROM AspNetUserTokens";
await using DbDataReader tokenReader = await tokenCommand.ExecuteReaderAsync();
while (await tokenReader.ReadAsync())
{
    for (int index = 0; index < tokenReader.FieldCount; index++)
    {
        Console.WriteLine($"  {tokenReader.GetName(index)} = {tokenReader.GetValue(index)}");
    }
}
await tokenReader.CloseAsync();

Console.WriteLine();
Console.WriteLine("Raw AspNetUserLogins values:");
await using DbCommand loginCommand = rawConnection.CreateCommand();
loginCommand.CommandText = "SELECT LoginId, LoginProvider, ProviderKey, ProviderDisplayName, RoutingHash, UserId FROM AspNetUserLogins";
await using DbDataReader loginReader = await loginCommand.ExecuteReaderAsync();
while (await loginReader.ReadAsync())
{
    for (int index = 0; index < loginReader.FieldCount; index++)
    {
        Console.WriteLine($"  {loginReader.GetName(index)} = {loginReader.GetValue(index)}");
    }
}
await loginReader.CloseAsync();

Console.WriteLine();
Console.WriteLine("Raw UserPasskeys values:");
await using DbCommand passkeyCommand = rawConnection.CreateCommand();
passkeyCommand.CommandText = "SELECT PasskeyId, ProtectedCredentialId, RoutingHash, PublicKey, PasskeyName, CreatedAt, SignCount, Transports, IsUserVerified, UserId FROM UserPasskeys";
await using DbDataReader passkeyReader = await passkeyCommand.ExecuteReaderAsync();
while (await passkeyReader.ReadAsync())
{
    for (int index = 0; index < passkeyReader.FieldCount; index++)
    {
        Console.WriteLine($"  {passkeyReader.GetName(index)} = {passkeyReader.GetValue(index)}");
    }
}

static KeyServiceEntry CreateKeySourceEntry(byte sourceKeyId, int offset) => new()
{
    KeySourceId = sourceKeyId,
    Type = KeyType.Block,
    Value = string.Create(4096, offset, static (span, start) =>
    {
        for (int index = 0; index < span.Length; index++)
        {
            span[index] = (char)('!' + ((index + start) % 90));
        }
    }),
    KeyHandleMask = "565342976",
    BlockSettings = new KeyBlockSettings { MinLength = 64, MaxLength = 128 }
};

internal sealed class DemoIdentityUserToken : EncryptedIdentityUserToken<string>;

[GenerateEncryptedIdentityLookup]
[GenerateEncryptedIdentityTokenStore("IdentityTokenLookup")]
[GenerateEncryptedIdentityClaimStores("IdentityLookup")]
[GenerateEncryptedIdentityLoginStore("IdentityLookup")]
[GenerateEncryptedIdentityPasskeyStore("IdentityLookup")]
internal sealed class DemoIdentityDbContext(
    DbContextOptions<DemoIdentityDbContext> options,
    IEntityDataProtectionService dataProtectionService,
    SourceKeyMapConfig sourceKeyMapConfig)
    : IdentityDbContext<
        EncryptedIdentityUser,
        EncryptedIdentityRole,
        string,
        EncryptedIdentityUserClaim,
        IdentityUserRole<string>,
        EncryptedIdentityUserLogin,
        EncryptedIdentityRoleClaim,
        DemoIdentityUserToken,
        EncryptedIdentityUserPasskey>(options)
{
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        modelBuilder.RemoveIdentityPlaintextLookupIndexes<EncryptedIdentityUser>();
        modelBuilder.RemoveIdentityPlaintextRoleLookupIndex<EncryptedIdentityRole>();
        modelBuilder.ConfigureEncryptedIdentityClaims<EncryptedIdentityUserClaim, EncryptedIdentityRoleClaim>();
        modelBuilder.ConfigureEncryptedIdentityLogins<EncryptedIdentityUserLogin>();
        modelBuilder.ConfigureEncryptedIdentityPasskeys<EncryptedIdentityUserPasskey>();
        modelBuilder.AddMrbrGeneratedEncryption(dataProtectionService, sourceKeyMapConfig);
    }
}
