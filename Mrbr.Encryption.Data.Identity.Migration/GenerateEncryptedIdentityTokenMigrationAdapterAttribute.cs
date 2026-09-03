namespace Mrbr.Encryption.Data.Identity.Migration;

/// <summary>Requests a source-generated adapter for an explicitly configured protected Identity token context.</summary>
[AttributeUsage(AttributeTargets.Class, AllowMultiple = false, Inherited = false)]
public sealed class GenerateEncryptedIdentityTokenMigrationAdapterAttribute : Attribute
{
}
