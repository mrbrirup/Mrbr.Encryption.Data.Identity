using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace Mrbr.Encryption.Data.Identity;

/// <summary>
/// Verifies that Identity email uniqueness agrees with the generated HMAC index.
/// </summary>
public sealed class EncryptedIdentityOptionsValidator : IValidateOptions<IdentityOptions>
{
    private readonly bool requireUniqueEmail;
    private readonly string userTypeName;

    /// <summary>
    /// Creates a validator for a generated Identity user model.
    /// </summary>
    /// <param name="requireUniqueEmail">Whether the generated email HMAC index is unique.</param>
    /// <param name="userTypeName">The user type used in validation errors.</param>
    public EncryptedIdentityOptionsValidator(bool requireUniqueEmail, string userTypeName)
    {
        this.requireUniqueEmail = requireUniqueEmail;
        this.userTypeName = string.IsNullOrWhiteSpace(userTypeName)
            ? throw new ArgumentException("A user type name is required.", nameof(userTypeName))
            : userTypeName;
    }

    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, IdentityOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.User.RequireUniqueEmail == requireUniqueEmail)
        {
            return ValidateOptionsResult.Success;
        }

        return ValidateOptionsResult.Fail(
            $"IdentityOptions.User.RequireUniqueEmail for '{userTypeName}' must be " +
            $"'{requireUniqueEmail}' to match the generated NormalizedEmail HMAC index.");
    }
}
