namespace Mrbr.Encryption.Data.Identity;

/// <summary>
/// Requests a source-generated keyed-hash lookup adapter for an Identity database context.
/// </summary>
[AttributeUsage(AttributeTargets.Class, AllowMultiple = false, Inherited = false)]
public sealed class GenerateEncryptedIdentityLookupAttribute : Attribute;
