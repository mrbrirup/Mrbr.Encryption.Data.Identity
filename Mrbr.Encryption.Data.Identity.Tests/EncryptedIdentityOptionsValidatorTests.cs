using Microsoft.AspNetCore.Identity;

namespace Mrbr.Encryption.Data.Identity.Tests;

public sealed class EncryptedIdentityOptionsValidatorTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Validate_SucceedsWhenIdentityOptionMatchesGeneratedIndex(bool requireUniqueEmail)
    {
        var validator = new EncryptedIdentityOptionsValidator(requireUniqueEmail, "Example.ApplicationUser");
        var options = new IdentityOptions();
        options.User.RequireUniqueEmail = requireUniqueEmail;

        Microsoft.Extensions.Options.ValidateOptionsResult result = validator.Validate(null, options);

        Assert.True(result.Succeeded);
    }

    [Theory]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public void Validate_FailsWhenIdentityOptionDisagreesWithGeneratedIndex(
        bool generatedIndexIsUnique,
        bool configuredRequireUniqueEmail)
    {
        var validator = new EncryptedIdentityOptionsValidator(
            generatedIndexIsUnique,
            "Example.ApplicationUser");
        var options = new IdentityOptions();
        options.User.RequireUniqueEmail = configuredRequireUniqueEmail;

        Microsoft.Extensions.Options.ValidateOptionsResult result = validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains("RequireUniqueEmail", result.FailureMessage, StringComparison.Ordinal);
        Assert.Contains(generatedIndexIsUnique.ToString(), result.FailureMessage, StringComparison.OrdinalIgnoreCase);
    }
}
