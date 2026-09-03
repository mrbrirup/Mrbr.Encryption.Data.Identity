namespace Mrbr.Encryption.Data.Identity.Migration.Console;

/// <summary>Identifies the provider-specific migration executor selected by the application bootstrap.</summary>
public enum IdentityTokenMigrationDatabaseProvider
{
    Sqlite = 0,
    PostgreSql = 1
}
