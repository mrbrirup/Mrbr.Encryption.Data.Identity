using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Mrbr.Encryption.Data.Common.Results;
using System.Security.Claims;

namespace Mrbr.Encryption.Data.Identity.Tests;

public sealed class EncryptedIdentityClaimStoreTests
{
    [Fact]
    public async Task UserStore_AddAndReplaceClaim_UpdatesCompositeRoute()
    {
        await using SqliteConnection connection = new("Data Source=:memory:");
        await connection.OpenAsync();
        await using TestContext context = CreateContext(connection);
        await context.Database.EnsureCreatedAsync();
        TestUser user = new() { Id = "user-1" };
        context.Users.Add(user);
        await context.SaveChangesAsync();
        StubClaimLookup lookup = new(context);
        using TestUserStore store = new(context, lookup);

        await store.AddClaimsAsync(user, [new Claim("permission", "read")]);
        TestUserClaim stored = await context.Set<TestUserClaim>().SingleAsync();
        Assert.Equal("U|user-1|permission|read", stored.RoutingHash);

        await store.ReplaceClaimAsync(user, new Claim("permission", "read"), new Claim("permission", "write"));
        Assert.Equal("write", stored.ClaimValue);
        Assert.Equal("U|user-1|permission|write", stored.RoutingHash);
    }

    [Fact]
    public async Task RoleStore_RemoveClaim_FailsClosedForHashCollisionCandidate()
    {
        await using TestContext context = CreateContext();
        StubClaimLookup lookup = new(context)
        {
            RoleCandidates = [new TestRoleClaim { RoleId = "other", ClaimType = "permission", ClaimValue = "read" }]
        };
        using TestRoleStore store = new(context, lookup);

        IdentityDataProtectionException exception = await Assert.ThrowsAsync<IdentityDataProtectionException>(() =>
            store.RemoveClaimAsync(new TestRole { Id = "role-1" }, new Claim("permission", "read")));

        Assert.Equal(ProtectionFailureCode.HashMismatch, exception.FailureCode);
    }

    private static TestContext CreateContext(SqliteConnection? connection = null) => new(
        connection is null
            ? new DbContextOptionsBuilder<TestContext>().UseSqlite("Data Source=:memory:").Options
            : new DbContextOptionsBuilder<TestContext>().UseSqlite(connection).Options);

    private sealed class TestUserStore(TestContext context, StubClaimLookup lookup) :
        EncryptedIdentityClaimsUserStore<TestUser, TestRole, TestContext, TestUserClaim,
            IdentityUserRole<string>, IdentityUserLogin<string>, IdentityUserToken<string>,
            TestRoleClaim, IdentityUserPasskey<string>>(
                context, new IdentityErrorDescriber(), new EmptyUserLookup(), lookup);

    private sealed class TestRoleStore(TestContext context, StubClaimLookup lookup) :
        EncryptedIdentityClaimsRoleStore<TestRole, TestContext, IdentityUserRole<string>, TestUserClaim, TestRoleClaim>(
            context, new IdentityErrorDescriber(), new EmptyRoleLookup(), lookup);

    private sealed class StubClaimLookup(TestContext context) : IEncryptedIdentityClaimLookup<TestUserClaim, TestRoleClaim>
    {
        public IReadOnlyList<TestRoleClaim> RoleCandidates { get; init; } = [];
        public ProtectionResult<string> ComputeUserRoutingHash(string userId, string claimType, string claimValue) =>
            ProtectionResult<string>.Success($"U|{userId}|{claimType}|{claimValue}");
        public ProtectionResult<string> ComputeRoleRoutingHash(string roleId, string claimType, string claimValue) =>
            ProtectionResult<string>.Success($"R|{roleId}|{claimType}|{claimValue}");
        public async Task<IReadOnlyList<TestUserClaim>> FindUserCandidatesAsync(string routingHash, CancellationToken cancellationToken = default) =>
            await context.Set<TestUserClaim>().Where(value => value.RoutingHash == routingHash).ToListAsync(cancellationToken);
        public Task<IReadOnlyList<TestRoleClaim>> FindRoleCandidatesAsync(string routingHash, CancellationToken cancellationToken = default) =>
            Task.FromResult(RoleCandidates);
    }

    private sealed class EmptyUserLookup : IEncryptedIdentityUserLookup<TestUser>
    {
        public Task<IReadOnlyList<TestUser>> FindByNormalizedUserNameMatchesAsync(string value, CancellationToken token = default) => Task.FromResult<IReadOnlyList<TestUser>>([]);
        public Task<IReadOnlyList<TestUser>> FindByNormalizedEmailMatchesAsync(string value, CancellationToken token = default) => Task.FromResult<IReadOnlyList<TestUser>>([]);
    }

    private sealed class EmptyRoleLookup : IEncryptedIdentityRoleLookup<TestRole>
    {
        public Task<IReadOnlyList<TestRole>> FindByNormalizedNameMatchesAsync(string value, CancellationToken token = default) => Task.FromResult<IReadOnlyList<TestRole>>([]);
    }

    private sealed class TestUser : IdentityUser;
    private sealed class TestRole : IdentityRole;
    private sealed class TestUserClaim : EncryptedIdentityUserClaim<string>;
    private sealed class TestRoleClaim : EncryptedIdentityRoleClaim<string>;
    private sealed class TestContext(DbContextOptions<TestContext> options) : IdentityDbContext<
        TestUser, TestRole, string, TestUserClaim, IdentityUserRole<string>, IdentityUserLogin<string>,
        TestRoleClaim, IdentityUserToken<string>, IdentityUserPasskey<string>>(options);
}
