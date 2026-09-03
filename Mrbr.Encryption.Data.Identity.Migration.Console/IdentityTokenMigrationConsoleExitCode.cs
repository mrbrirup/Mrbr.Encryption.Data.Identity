namespace Mrbr.Encryption.Data.Identity.Migration.Console;

/// <summary>Stable process exit codes for operator automation.</summary>
public enum IdentityTokenMigrationConsoleExitCode
{
    /// <summary>The requested operation completed successfully.</summary>
    Success = 0,
    /// <summary>The command line was invalid or a required acknowledgement was absent.</summary>
    Usage = 2,
    /// <summary>The requested migration checkpoint does not exist.</summary>
    MigrationNotFound = 3,
    /// <summary>The migration library returned a known failure code.</summary>
    MigrationFailure = 10,
    /// <summary>An unexpected configuration, provider, or programming failure reached the process boundary.</summary>
    SoftwareFailure = 70,
    /// <summary>The operation was cancelled.</summary>
    Cancelled = 130
}
