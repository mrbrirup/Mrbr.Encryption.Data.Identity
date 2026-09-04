using Microsoft.Extensions.DependencyInjection;

namespace Mrbr.Encryption.Data.Identity;

/// <summary>Registers canonical Identity key serialization.</summary>
public static class IdentityKeyServiceCollectionExtensions
{
    /// <summary>Registers built-in canonical serialization for string, GUID, and integer keys.</summary>
    public static IServiceCollection AddMrbrIdentityKeySerializer<TKey>(this IServiceCollection services)
        where TKey : IEquatable<TKey>
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddSingleton<IIdentityKeySerializer<TKey>, IdentityKeySerializer<TKey>>();
        return services;
    }

    /// <summary>Registers an application serializer for a strongly typed Identity key.</summary>
    public static IServiceCollection AddMrbrIdentityKeySerializer<TKey, TSerializer>(this IServiceCollection services)
        where TKey : IEquatable<TKey>
        where TSerializer : class, IIdentityKeySerializer<TKey>
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddSingleton<IIdentityKeySerializer<TKey>, TSerializer>();
        return services;
    }
}
