using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Mrbr.Encryption.Data.Identity.Tests;

public sealed class EncryptedIdentityUserStoreTests
{
    [Fact]
    public async Task FindByNameAsync_ReturnsTheSingleVerifiedMatch()
    {
        TestUser expected = new() { Id = "1", UserName = "alice" };
        StubLookup lookup = new() { UserNameMatches = [expected] };
        await using TestContext context = CreateContext();
        using TestStore store = new(context, lookup);

        TestUser? actual = await store.FindByNameAsync("ALICE");

        Assert.Same(expected, actual);
        Assert.Equal("ALICE", lookup.LastUserName);
    }

    [Fact]
    public async Task FindByEmailAsync_ReturnsNullWhenThereIsNoVerifiedMatch()
    {
        StubLookup lookup = new();
        await using TestContext context = CreateContext();
        using TestStore store = new(context, lookup);

        TestUser? actual = await store.FindByEmailAsync("ALICE@EXAMPLE.TEST");

        Assert.Null(actual);
        Assert.Equal("ALICE@EXAMPLE.TEST", lookup.LastEmail);
    }

    [Fact]
    public async Task FindByNameAsync_RejectsMultipleVerifiedPlaintextMatches()
    {
        StubLookup lookup = new()
        {
            UserNameMatches =
            [
                new TestUser { Id = "1" },
                new TestUser { Id = "2" }
            ]
        };
        await using TestContext context = CreateContext();
        using TestStore store = new(context, lookup);

        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => store.FindByNameAsync("ALICE"));

        Assert.Contains("multiple verified plaintext matches", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task FindByEmailAsync_RejectsAmbiguousVerifiedMatchesInNonUniqueMode()
    {
        StubLookup lookup = new()
        {
            EmailMatches =
            [
                new TestUser { Id = "1" },
                new TestUser { Id = "2" }
            ]
        };
        await using TestContext context = CreateContext();
        using TestStore store = new(context, lookup);

        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => store.FindByEmailAsync("SHARED@EXAMPLE.TEST"));

        Assert.Contains("multiple verified plaintext matches", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task FindByEmailAsync_PassesCancellationTokenToLookup()
    {
        using CancellationTokenSource cancellation = new();
        StubLookup lookup = new();
        await using TestContext context = CreateContext();
        using TestStore store = new(context, lookup);

        await store.FindByEmailAsync("ALICE@EXAMPLE.TEST", cancellation.Token);

        Assert.Equal(cancellation.Token, lookup.LastCancellationToken);
    }

    private static TestContext CreateContext()
    {
        DbContextOptions<TestContext> options = new DbContextOptionsBuilder<TestContext>()
            .UseSqlite("Data Source=:memory:")
            .Options;
        return new TestContext(options);
    }

    private sealed class TestStore(
        TestContext context,
        IEncryptedIdentityUserLookup<TestUser> lookup)
        : EncryptedIdentityUserStore<TestUser, IdentityRole, TestContext>(
            context,
            new IdentityErrorDescriber(),
            lookup);

    private sealed class StubLookup : IEncryptedIdentityUserLookup<TestUser>
    {
        public IReadOnlyList<TestUser> UserNameMatches { get; init; } = [];

        public IReadOnlyList<TestUser> EmailMatches { get; init; } = [];

        public string? LastUserName { get; private set; }

        public string? LastEmail { get; private set; }

        public CancellationToken LastCancellationToken { get; private set; }

        public Task<IReadOnlyList<TestUser>> FindByNormalizedUserNameMatchesAsync(
            string normalizedUserName,
            CancellationToken cancellationToken = default)
        {
            LastUserName = normalizedUserName;
            LastCancellationToken = cancellationToken;
            return Task.FromResult(UserNameMatches);
        }

        public Task<IReadOnlyList<TestUser>> FindByNormalizedEmailMatchesAsync(
            string normalizedEmail,
            CancellationToken cancellationToken = default)
        {
            LastEmail = normalizedEmail;
            LastCancellationToken = cancellationToken;
            return Task.FromResult(EmailMatches);
        }
    }

    private sealed class TestUser : IdentityUser;

    private sealed class TestContext(DbContextOptions<TestContext> options)
        : IdentityDbContext<TestUser>(options);
}
