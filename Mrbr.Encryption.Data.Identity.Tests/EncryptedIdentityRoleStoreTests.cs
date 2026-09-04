using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Mrbr.Encryption.Data.Identity.Tests;

public sealed class EncryptedIdentityRoleStoreTests
{
    [Fact]
    public async Task FindByNameAsync_ReturnsTheSingleVerifiedMatch()
    {
        TestRole expected = new() { Id = "1", Name = "Administrator" };
        StubLookup lookup = new() { Matches = [expected] };
        await using TestContext context = CreateContext();
        using TestStore store = new(context, lookup);

        TestRole? actual = await store.FindByNameAsync("ADMINISTRATOR");

        Assert.Same(expected, actual);
        Assert.Equal("ADMINISTRATOR", lookup.LastNormalizedName);
    }

    [Fact]
    public async Task FindByNameAsync_ReturnsNullForNoVerifiedMatch()
    {
        StubLookup lookup = new();
        await using TestContext context = CreateContext();
        using TestStore store = new(context, lookup);

        Assert.Null(await store.FindByNameAsync("MISSING"));
    }

    [Fact]
    public async Task FindByNameAsync_FailsClosedForMultipleVerifiedMatches()
    {
        StubLookup lookup = new()
        {
            Matches = [new TestRole { Id = "1" }, new TestRole { Id = "2" }]
        };
        await using TestContext context = CreateContext();
        using TestStore store = new(context, lookup);

        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => store.FindByNameAsync("ADMINISTRATOR"));

        Assert.Contains("multiple verified plaintext matches", exception.Message, StringComparison.Ordinal);
    }

    private static TestContext CreateContext() => new(
        new DbContextOptionsBuilder<TestContext>().UseSqlite("Data Source=:memory:").Options);

    private sealed class TestStore(
        TestContext context,
        IEncryptedIdentityRoleLookup<TestRole> lookup)
        : EncryptedIdentityRoleStore<
            TestRole,
            TestContext,
            IdentityUserRole<string>,
            IdentityRoleClaim<string>>(context, new IdentityErrorDescriber(), lookup);

    private sealed class StubLookup : IEncryptedIdentityRoleLookup<TestRole>
    {
        public IReadOnlyList<TestRole> Matches { get; init; } = [];
        public string? LastNormalizedName { get; private set; }

        public Task<IReadOnlyList<TestRole>> FindByNormalizedNameMatchesAsync(
            string normalizedName,
            CancellationToken cancellationToken = default)
        {
            LastNormalizedName = normalizedName;
            return Task.FromResult(Matches);
        }
    }

    private sealed class TestRole : IdentityRole;

    private sealed class TestUser : IdentityUser;

    private sealed class TestContext(DbContextOptions<TestContext> options)
        : IdentityDbContext<TestUser, TestRole, string>(options);
}
