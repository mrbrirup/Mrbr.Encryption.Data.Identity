namespace Mrbr.Encryption.Data.Identity.Migration.Console;

/// <summary>Exposes only the configured services required by the selected provider migration operator.</summary>
public interface IIdentityTokenMigrationConsoleSession : IAsyncDisposable
{
    /// <summary>Gets the provider executor selected by the application. SQLite remains the compatibility default.</summary>
    IdentityTokenMigrationDatabaseProvider DatabaseProvider => IdentityTokenMigrationDatabaseProvider.Sqlite;

    /// <summary>Gets the externally configured provider connection string. It is never written to console output.</summary>
    string ConnectionString { get; }

    /// <summary>Gets the application-generated protection adapter.</summary>
    IIdentityTokenMigrationProtectionAdapter ProtectionAdapter { get; }

    /// <summary>Gets the application-generated post-cutover runtime verifier.</summary>
    IIdentityTokenMigrationRuntimeVerifier RuntimeVerifier { get; }
}
