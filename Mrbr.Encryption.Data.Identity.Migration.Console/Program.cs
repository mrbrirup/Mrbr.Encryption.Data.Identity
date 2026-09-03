using System.Reflection;
using System.Runtime.Loader;
using Mrbr.Encryption.Data.Identity.Migration.Console;

using CancellationTokenSource cancellation = new();
System.Console.CancelKeyPress += (_, eventArgs) =>
{
    eventArgs.Cancel = true;
    cancellation.Cancel();
};
return await IdentityTokenMigrationConsoleProgram.RunAsync(
    args,
    System.Console.Out,
    System.Console.Error,
    cancellation.Token).ConfigureAwait(false);

/// <summary>Loads an application-owned bootstrap and dispatches one operator command.</summary>
public static class IdentityTokenMigrationConsoleProgram
{
    /// <summary>Runs the executable host with injectable output streams for verification.</summary>
    public static async Task<int> RunAsync(
        IReadOnlyList<string> args,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);
        if (args.Count == 1 && args[0] is "help" or "--help" or "-h")
        {
            await WriteHostHelpAsync(output).ConfigureAwait(false);
            return 0;
        }

        if (args.Count == 1 && args[0] == "new-id")
        {
            await output.WriteLineAsync(Guid.CreateVersion7().ToString("D")).ConfigureAwait(false);
            return 0;
        }

        if (!TryRemoveGlobalOption(args, "--bootstrap-assembly", out string? assemblyOption, out string[] remaining) ||
            !TryRemoveGlobalOption(remaining, "--bootstrap-type", out string? typeOption, out remaining))
        {
            await error.WriteLineAsync(
                "usage-error=Specify --bootstrap-assembly and --bootstrap-type, or their MRBR_IDENTITY_MIGRATION_* environment variables.")
                .ConfigureAwait(false);
            return (int)IdentityTokenMigrationConsoleExitCode.Usage;
        }

        string? assemblyPath = assemblyOption ??
            Environment.GetEnvironmentVariable("MRBR_IDENTITY_MIGRATION_BOOTSTRAP_ASSEMBLY");
        string? typeName = typeOption ??
            Environment.GetEnvironmentVariable("MRBR_IDENTITY_MIGRATION_BOOTSTRAP_TYPE");
        if (string.IsNullOrWhiteSpace(assemblyPath) || string.IsNullOrWhiteSpace(typeName))
        {
            await error.WriteLineAsync("usage-error=The application bootstrap assembly and type are required.")
                .ConfigureAwait(false);
            return (int)IdentityTokenMigrationConsoleExitCode.Usage;
        }

        try
        {
            string fullPath = Path.GetFullPath(assemblyPath);
            AssemblyDependencyResolver resolver = new(fullPath);
            AssemblyLoadContext.Default.Resolving += Resolve;
            try
            {
                Assembly assembly = AssemblyLoadContext.Default.LoadFromAssemblyPath(fullPath);
                Type type = assembly.GetType(typeName, throwOnError: true, ignoreCase: false)!;
                if (!typeof(IIdentityTokenMigrationConsoleBootstrap).IsAssignableFrom(type) ||
                    type.IsAbstract ||
                    type.GetConstructor(Type.EmptyTypes) is null)
                {
                    await error.WriteLineAsync(
                        "bootstrap-error=The bootstrap type must be concrete, public, parameterless, and implement IIdentityTokenMigrationConsoleBootstrap.")
                        .ConfigureAwait(false);
                    return (int)IdentityTokenMigrationConsoleExitCode.Usage;
                }

                var bootstrap = (IIdentityTokenMigrationConsoleBootstrap)Activator.CreateInstance(type)!;
                await using IIdentityTokenMigrationConsoleSession session =
                    await bootstrap.CreateSessionAsync(cancellationToken).ConfigureAwait(false);
                var commandConsole = new SqliteIdentityTokenMigrationConsole(
                    session.DatabaseProvider,
                    session.ConnectionString,
                    session.ProtectionAdapter,
                    session.RuntimeVerifier,
                    output,
                    error);
                return await commandConsole.RunAsync(remaining, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                AssemblyLoadContext.Default.Resolving -= Resolve;
            }

            Assembly? Resolve(AssemblyLoadContext context, AssemblyName name)
            {
                string? dependencyPath = resolver.ResolveAssemblyToPath(name);
                return dependencyPath is null ? null : context.LoadFromAssemblyPath(dependencyPath);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            await error.WriteLineAsync("cancelled=true").ConfigureAwait(false);
            return (int)IdentityTokenMigrationConsoleExitCode.Cancelled;
        }
        catch (Exception exception)
        {
            await error.WriteLineAsync($"operator-error={exception.GetType().Name}").ConfigureAwait(false);
            return (int)IdentityTokenMigrationConsoleExitCode.SoftwareFailure;
        }
    }

    private static bool TryRemoveGlobalOption(
        IReadOnlyList<string> args,
        string option,
        out string? value,
        out string[] remaining)
    {
        value = null;
        var retained = new List<string>(args.Count);
        for (int index = 0; index < args.Count; index++)
        {
            if (!string.Equals(args[index], option, StringComparison.Ordinal))
            {
                retained.Add(args[index]);
                continue;
            }

            if (value is not null || ++index >= args.Count || args[index].StartsWith("--", StringComparison.Ordinal))
            {
                remaining = [];
                return false;
            }

            value = args[index];
        }

        remaining = retained.ToArray();
        return true;
    }

    private static async ValueTask WriteHostHelpAsync(TextWriter output) => await output.WriteLineAsync(
        "Mrbr protected Identity token migration operator\n" +
        "Supply --bootstrap-assembly <path> --bootstrap-type <full-type-name> before one migration command.\n" +
        "The equivalent environment variables are MRBR_IDENTITY_MIGRATION_BOOTSTRAP_ASSEMBLY and " +
        "MRBR_IDENTITY_MIGRATION_BOOTSTRAP_TYPE.\n" +
        "Run new-id to create a UUIDv7 migration identifier. No command performs more than one explicit stage transition.")
        .ConfigureAwait(false);
}
