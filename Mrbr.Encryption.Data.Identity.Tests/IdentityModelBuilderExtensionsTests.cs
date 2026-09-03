using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;

namespace Mrbr.Encryption.Data.Identity.Tests;

public sealed class IdentityModelBuilderExtensionsTests
{
    [Fact]
    public void RemoveIdentityPlaintextLookupIndexes_RemovesUserNameAndEmailIndexes()
    {
        DbContextOptions<TestContext> options = new DbContextOptionsBuilder<TestContext>()
            .UseSqlite("Data Source=:memory:")
            .Options;
        using TestContext context = new(options);

        IReadOnlyList<IReadOnlyIndex> indexes = context.Model
            .FindEntityType(typeof(TestUser))!
            .GetIndexes()
            .ToArray();

        Assert.DoesNotContain(indexes, static index => index.Properties.Any(static property =>
            property.Name is nameof(IdentityUser.NormalizedUserName)
                or nameof(IdentityUser.NormalizedEmail)));
    }

    private sealed class TestUser : IdentityUser;

    private sealed class TestContext(DbContextOptions<TestContext> options)
        : IdentityDbContext<TestUser>(options)
    {
        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            builder.RemoveIdentityPlaintextLookupIndexes<TestUser>();
        }
    }
}
