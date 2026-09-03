using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;

namespace Mrbr.Encryption.Data.Identity;

/// <summary>
/// Model configuration for encrypted ASP.NET Core Identity entities.
/// </summary>
public static class IdentityModelBuilderExtensions
{
    /// <summary>
    /// Removes Identity's conventional indexes over normalized username and email properties.
    /// Generated keyed-HMAC indexes should be configured after this call.
    /// </summary>
    public static ModelBuilder RemoveIdentityPlaintextLookupIndexes<TUser>(
        this ModelBuilder modelBuilder)
        where TUser : IdentityUser
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);

        IMutableEntityType userEntity = modelBuilder.Entity<TUser>().Metadata;
        foreach (IMutableIndex index in userEntity.GetIndexes()
                     .Where(static index => index.Properties.Any(static property =>
                         property.Name is nameof(IdentityUser.NormalizedUserName)
                             or nameof(IdentityUser.NormalizedEmail)))
                     .ToArray())
        {
            userEntity.RemoveIndex(index);
        }

        return modelBuilder;
    }
}
