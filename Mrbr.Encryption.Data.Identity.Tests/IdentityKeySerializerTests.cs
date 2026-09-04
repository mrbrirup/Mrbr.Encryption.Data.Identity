using System.Globalization;

namespace Mrbr.Encryption.Data.Identity.Tests;

public sealed class IdentityKeySerializerTests
{
    [Fact]
    public void BuiltInSerializer_UsesCanonicalGuidAndIntegerRepresentations()
    {
        Assert.Equal("00112233-4455-6677-8899-aabbccddeeff",
            new IdentityKeySerializer<Guid>().Serialize(Guid.Parse("00112233-4455-6677-8899-AABBCCDDEEFF")));

        CultureInfo original = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("ar-SA");
            Assert.Equal("-123456789", new IdentityKeySerializer<long>().Serialize(-123456789));
        }
        finally
        {
            CultureInfo.CurrentCulture = original;
        }
    }

    [Fact]
    public void BuiltInSerializer_RequiresExplicitSerializerForStronglyTypedId()
    {
        Assert.Throws<NotSupportedException>(() =>
            new IdentityKeySerializer<AccountId>().Serialize(new AccountId(Guid.NewGuid())));
    }

    private readonly record struct AccountId(Guid Value);
}
