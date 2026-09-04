using System.Globalization;

namespace Mrbr.Encryption.Data.Identity;

/// <summary>Produces the stable, culture-independent representation used in protected Identity routes.</summary>
public interface IIdentityKeySerializer<in TKey>
    where TKey : IEquatable<TKey>
{
    /// <summary>Serializes an Identity key to its canonical route component.</summary>
    string Serialize(TKey key);
}

/// <summary>Canonical serializer for Identity's common scalar key types.</summary>
public sealed class IdentityKeySerializer<TKey> : IIdentityKeySerializer<TKey>
    where TKey : IEquatable<TKey>
{
    /// <inheritdoc />
    public string Serialize(TKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return key switch
        {
            Guid value => value.ToString("D", CultureInfo.InvariantCulture).ToLowerInvariant(),
            byte value => value.ToString(CultureInfo.InvariantCulture),
            sbyte value => value.ToString(CultureInfo.InvariantCulture),
            short value => value.ToString(CultureInfo.InvariantCulture),
            ushort value => value.ToString(CultureInfo.InvariantCulture),
            int value => value.ToString(CultureInfo.InvariantCulture),
            uint value => value.ToString(CultureInfo.InvariantCulture),
            long value => value.ToString(CultureInfo.InvariantCulture),
            ulong value => value.ToString(CultureInfo.InvariantCulture),
            string value => value,
            _ => throw new NotSupportedException(
                $"Identity key type '{typeof(TKey)}' requires an application IIdentityKeySerializer<{typeof(TKey).Name}> registration.")
        };
    }
}
