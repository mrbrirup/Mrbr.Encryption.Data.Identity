using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Mrbr.Encryption.Data.Common.Results;
using Mrbr.Encryption.Data.EntityFramework.Services;

namespace Mrbr.Encryption.Data.Identity.Tests;

public sealed class EncryptedIdentityTokenTests
{
    [Fact]
    public void Constructor_CreatesVersion7Guid()
    {
        TestUserToken token = new();

        Assert.NotEqual(Guid.Empty, token.TokenId);
        Assert.Equal(7, token.TokenId.Version);
    }

    [Fact]
    public void ConfigureEncryptedIdentityTokens_ReplacesCompositePrimaryKey()
    {
        using TestTokenContext context = CreateContext();
        var entity = context.Model.FindEntityType(typeof(TestUserToken))!;

        Assert.Equal(
            [nameof(EncryptedIdentityUserToken<string>.TokenId)],
            entity.FindPrimaryKey()!.Properties.Select(property => property.Name));
        Assert.Contains(entity.GetIndexes(), index =>
            index.IsUnique && index.Properties.Single().Name == nameof(EncryptedIdentityUserToken<string>.RoutingHash));
    }

    [Fact]
    public async Task TokenStore_RoundTripsAndRetainsVersion7SurrogateKey()
    {
        await using TestTokenContext context = CreateContext();
        await context.Database.OpenConnectionAsync();
        await context.Database.EnsureCreatedAsync();
        TestUser user = new() { Id = "user-1", UserName = "alice" };
        context.Users.Add(user);
        await context.SaveChangesAsync();

        TestTokenLookup tokenLookup = new(context);
        using TestTokenStore store = new(context, new EmptyUserLookup(), tokenLookup);
        await store.SetTokenAsync(user, "provider", "name", "secret", CancellationToken.None);
        await context.SaveChangesAsync();

        TestUserToken first = await context.Set<TestUserToken>().SingleAsync();
        Guid firstId = first.TokenId;
        Assert.Equal(7, firstId.Version);
        Assert.Equal("secret", await store.GetTokenAsync(user, "provider", "name", CancellationToken.None));

        await store.SetTokenAsync(user, "provider", "name", "replacement", CancellationToken.None);
        await context.SaveChangesAsync();

        TestUserToken replacement = await context.Set<TestUserToken>().SingleAsync();
        Assert.Equal(firstId, replacement.TokenId);
        Assert.Equal("replacement", await store.GetTokenAsync(user, "provider", "name", CancellationToken.None));

        await store.RemoveTokenAsync(user, "provider", "name", CancellationToken.None);
        await context.SaveChangesAsync();
        Assert.Empty(await context.Set<TestUserToken>().ToListAsync());
    }

    [Theory]
    [InlineData(ProtectionFailureCode.KeyNotFound)]
    [InlineData(ProtectionFailureCode.KeyUnavailable)]
    [InlineData(ProtectionFailureCode.KeyRetired)]
    public async Task TokenStore_TranslatesRoutingFailureAtIdentityBoundary(ProtectionFailureCode failureCode)
    {
        await using TestTokenContext context = CreateContext();
        TestUser user = new() { Id = "user-1" };
        using TestTokenStore store = new(
            context,
            new EmptyUserLookup(),
            new FailedTokenLookup(failureCode));

        IdentityDataProtectionException exception = await Assert.ThrowsAsync<IdentityDataProtectionException>(
            () => store.GetTokenAsync(user, "provider", "name", CancellationToken.None));

        Assert.Equal(failureCode, exception.FailureCode);
    }

    [Fact]
    public async Task TokenStore_RejectsHashCollisionWithoutReturningWrongToken()
    {
        await using TestTokenContext context = CreateContext();
        TestUser user = new() { Id = "user-1" };
        TestUserToken collision = new()
        {
            UserId = user.Id,
            LoginProvider = "different-provider",
            Name = "different-name",
            Value = "wrong-secret",
            RoutingHash = new string('C', 64)
        };
        using TestTokenStore store = new(
            context,
            new EmptyUserLookup(),
            new CandidateTokenLookup(collision));

        IdentityDataProtectionException exception = await Assert.ThrowsAsync<IdentityDataProtectionException>(
            () => store.GetTokenAsync(user, "provider", "name", CancellationToken.None));

        Assert.Equal(ProtectionFailureCode.HashMismatch, exception.FailureCode);
        Assert.DoesNotContain("different-provider", exception.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("wrong-secret", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TokenStore_TranslatesCorruptCandidateMaterialization()
    {
        await using TestTokenContext context = CreateContext();
        TestUser user = new() { Id = "user-1" };
        using TestTokenStore store = new(
            context,
            new EmptyUserLookup(),
            new ThrowingTokenLookup(new FormatException("ciphertext was corrupt")));

        IdentityDataProtectionException exception = await Assert.ThrowsAsync<IdentityDataProtectionException>(
            () => store.GetTokenAsync(user, "provider", "name", CancellationToken.None));

        Assert.Equal(ProtectionFailureCode.InvalidPayload, exception.FailureCode);
        Assert.DoesNotContain("ciphertext was corrupt", exception.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("provider", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TokenStore_ConcurrentInsertPreservesOneLogicalRoute()
    {
        string databasePath = Path.Combine(Path.GetTempPath(), $"mrbr-token-{Guid.NewGuid():N}.db");
        try
        {
            DbContextOptions<TestTokenContext> options = new DbContextOptionsBuilder<TestTokenContext>()
                .UseSqlite($"Data Source={databasePath};Default Timeout=10;Pooling=False")
                .Options;
            await using (TestTokenContext setup = new(options))
            {
                await setup.Database.EnsureCreatedAsync();
                setup.Users.Add(new TestUser { Id = "user-1", UserName = "alice" });
                await setup.SaveChangesAsync();
            }

            using Barrier barrier = new(2);
            await using TestTokenContext firstContext = new(options);
            await using TestTokenContext secondContext = new(options);
            using TestTokenStore firstStore = new(firstContext, new EmptyUserLookup(), new BarrierTokenLookup(firstContext, barrier));
            using TestTokenStore secondStore = new(secondContext, new EmptyUserLookup(), new BarrierTokenLookup(secondContext, barrier));
            TestUser firstUser = new() { Id = "user-1" };
            TestUser secondUser = new() { Id = "user-1" };

            await Task.WhenAll(
                firstStore.SetTokenAsync(firstUser, "provider", "name", "first", CancellationToken.None),
                secondStore.SetTokenAsync(secondUser, "provider", "name", "second", CancellationToken.None));

            await using TestTokenContext verification = new(options);
            List<TestUserToken> rows = await verification.Set<TestUserToken>().AsNoTracking().ToListAsync();
            TestUserToken row = Assert.Single(rows);
            Assert.Equal(7, row.TokenId.Version);
            Assert.Contains(row.Value, new[] { "first", "second" });
        }
        finally
        {
            File.Delete(databasePath);
        }
    }

    private static TestTokenContext CreateContext()
    {
        DbContextOptions<TestTokenContext> options = new DbContextOptionsBuilder<TestTokenContext>()
            .UseSqlite("Data Source=:memory:")
            .Options;
        return new TestTokenContext(options);
    }

    private sealed class TestUser : IdentityUser;

    private sealed class TestUserToken : EncryptedIdentityUserToken<string>;

    private sealed class TestTokenContext(DbContextOptions<TestTokenContext> options)
        : IdentityDbContext<
            TestUser,
            IdentityRole,
            string,
            IdentityUserClaim<string>,
            IdentityUserRole<string>,
            IdentityUserLogin<string>,
            IdentityRoleClaim<string>,
            TestUserToken,
            IdentityUserPasskey<string>>(options)
    {
        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            builder.ConfigureEncryptedIdentityTokens<TestUserToken>();
        }
    }

    private sealed class TestTokenStore(
        TestTokenContext context,
        IEncryptedIdentityUserLookup<TestUser> userLookup,
        IEncryptedIdentityTokenLookup<TestUserToken> tokenLookup)
        : EncryptedIdentityTokenUserStore<
            TestUser,
            IdentityRole,
            TestTokenContext,
            IdentityUserClaim<string>,
            IdentityUserRole<string>,
            IdentityUserLogin<string>,
            TestUserToken,
            IdentityRoleClaim<string>,
            IdentityUserPasskey<string>>(context, new IdentityErrorDescriber(), userLookup, tokenLookup);

    private sealed class EmptyUserLookup : IEncryptedIdentityUserLookup<TestUser>
    {
        public Task<IReadOnlyList<TestUser>> FindByNormalizedUserNameMatchesAsync(
            string normalizedUserName,
            CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<TestUser>>([]);

        public Task<IReadOnlyList<TestUser>> FindByNormalizedEmailMatchesAsync(
            string normalizedEmail,
            CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<TestUser>>([]);
    }

    private sealed class TestTokenLookup(TestTokenContext context) : IEncryptedIdentityTokenLookup<TestUserToken>
    {
        public ProtectionResult<string> ComputeRoutingHash(string userId, string loginProvider, string name)
        {
            byte[] input = CompositeHashInputEncoder.Encode("Mrbr.Encryption.Data.Identity/UserTokenRoute", [userId, loginProvider, name]);
            try
            {
                return ProtectionResult<string>.Success(Convert.ToHexString(SHA256.HashData(input)));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(input);
            }
        }

        public async Task<IReadOnlyList<TestUserToken>> FindCandidatesAsync(
            string routingHash,
            CancellationToken cancellationToken = default) =>
            await context.Set<TestUserToken>()
                .Where(token => token.RoutingHash == routingHash)
                .ToListAsync(cancellationToken);
    }

    private sealed class FailedTokenLookup(ProtectionFailureCode code) : IEncryptedIdentityTokenLookup<TestUserToken>
    {
        public ProtectionResult<string> ComputeRoutingHash(string userId, string loginProvider, string name) =>
            ProtectionResult<string>.Failure(code);

        public Task<IReadOnlyList<TestUserToken>> FindCandidatesAsync(
            string routingHash,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();
    }

    private sealed class CandidateTokenLookup(params TestUserToken[] candidates) : IEncryptedIdentityTokenLookup<TestUserToken>
    {
        public ProtectionResult<string> ComputeRoutingHash(string userId, string loginProvider, string name) =>
            ProtectionResult<string>.Success(new string('C', 64));

        public Task<IReadOnlyList<TestUserToken>> FindCandidatesAsync(
            string routingHash,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<TestUserToken>>(candidates);
    }

    private sealed class ThrowingTokenLookup(Exception exception) : IEncryptedIdentityTokenLookup<TestUserToken>
    {
        public ProtectionResult<string> ComputeRoutingHash(string userId, string loginProvider, string name) =>
            ProtectionResult<string>.Success(new string('C', 64));

        public Task<IReadOnlyList<TestUserToken>> FindCandidatesAsync(
            string routingHash,
            CancellationToken cancellationToken = default) =>
            Task.FromException<IReadOnlyList<TestUserToken>>(exception);
    }

    private sealed class BarrierTokenLookup(TestTokenContext context, Barrier barrier) : IEncryptedIdentityTokenLookup<TestUserToken>
    {
        private int _queryCount;

        public ProtectionResult<string> ComputeRoutingHash(string userId, string loginProvider, string name)
        {
            byte[] input = CompositeHashInputEncoder.Encode("Mrbr.Encryption.Data.Identity/UserTokenRoute", [userId, loginProvider, name]);
            try
            {
                return ProtectionResult<string>.Success(Convert.ToHexString(SHA256.HashData(input)));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(input);
            }
        }

        public async Task<IReadOnlyList<TestUserToken>> FindCandidatesAsync(
            string routingHash,
            CancellationToken cancellationToken = default)
        {
            if (Interlocked.Increment(ref _queryCount) == 1)
            {
                bool synchronized = await Task.Run(
                    () => barrier.SignalAndWait(TimeSpan.FromSeconds(10), cancellationToken),
                    cancellationToken);
                Assert.True(synchronized);
            }

            return await context.Set<TestUserToken>()
                .Where(token => token.RoutingHash == routingHash)
                .Take(2)
                .ToListAsync(cancellationToken);
        }
    }
}
