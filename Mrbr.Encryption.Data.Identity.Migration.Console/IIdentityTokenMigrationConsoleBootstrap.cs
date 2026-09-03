namespace Mrbr.Encryption.Data.Identity.Migration.Console;

/// <summary>Application-owned entry point that supplies deployment configuration and generated migration services.</summary>
public interface IIdentityTokenMigrationConsoleBootstrap
{
    /// <summary>Creates one scoped operator session without generating or replacing any key.</summary>
    ValueTask<IIdentityTokenMigrationConsoleSession> CreateSessionAsync(
        CancellationToken cancellationToken = default);
}
