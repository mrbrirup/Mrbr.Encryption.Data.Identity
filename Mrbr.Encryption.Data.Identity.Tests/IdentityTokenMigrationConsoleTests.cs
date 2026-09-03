using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using Mrbr.Encryption.Data.Identity.Migration;
using Mrbr.Encryption.Data.Identity.Migration.Console;
using Mrbr.Encryption.Data.Identity.Migration.Sqlite;

namespace Mrbr.Encryption.Data.Identity.Tests;

public sealed class IdentityTokenMigrationConsoleTests
{
    [Fact]
    public async Task ExecutableHost_LoadsApplicationBootstrapWithoutPrintingConfiguration()
    {
        string connectionString = "Data Source=:memory:";
        OperatorConsoleTestBootstrap.ConnectionString = connectionString;
        try
        {
            using StringWriter output = new(CultureInfo.InvariantCulture);
            using StringWriter error = new(CultureInfo.InvariantCulture);
            int exitCode = await global::IdentityTokenMigrationConsoleProgram.RunAsync(
                [
                    "--bootstrap-assembly", typeof(OperatorConsoleTestBootstrap).Assembly.Location,
                    "--bootstrap-type", typeof(OperatorConsoleTestBootstrap).FullName!,
                    "status", "--migration", Guid.CreateVersion7().ToString("D")
                ],
                output,
                error);

            Assert.Equal((int)IdentityTokenMigrationConsoleExitCode.MigrationNotFound, exitCode);
            Assert.Equal(1, OperatorConsoleTestBootstrap.SessionsCreated);
            Assert.DoesNotContain(connectionString, output.ToString(), StringComparison.Ordinal);
            Assert.DoesNotContain(connectionString, error.ToString(), StringComparison.Ordinal);
        }
        finally
        {
            OperatorConsoleTestBootstrap.Reset();
        }
    }

    [Fact]
    public async Task Console_RequiresApprovalsAndRunsCompleteExplicitWorkflow()
    {
        string databasePath = Path.Combine(Path.GetTempPath(), $"mrbr-operator-{Guid.NewGuid():N}.db");
        string connectionString = $"Data Source={databasePath};Foreign Keys=True;Pooling=False";
        try
        {
            await CreateLegacyDatabaseAsync(connectionString);
            Guid migrationId = Guid.CreateVersion7();
            using StringWriter output = new(CultureInfo.InvariantCulture);
            using StringWriter error = new(CultureInfo.InvariantCulture);
            var console = new SqliteIdentityTokenMigrationConsole(
                connectionString,
                new OperatorProtectionAdapter(),
                new SuccessfulRuntimeVerifier(),
                output,
                error);
            string id = migrationId.ToString("D");

            Assert.Equal((int)IdentityTokenMigrationConsoleExitCode.Usage, await console.RunAsync(
                ["preflight", "--migration", id]));
            Assert.Equal(0, await CountObjectsAsync(connectionString, "__MrbrIdentityTokenMigrationCheckpoints"));

            AssertSuccess(await console.RunAsync(
                [
                    "preflight", "--migration", id,
                    "--confirm-maintenance-read-only",
                    "--confirm-restorable-backup",
                    "--confirm-configuration-and-keys",
                    "--confirm-permissions-and-capacity"
                ]));
            Assert.Equal((int)IdentityTokenMigrationConsoleExitCode.MigrationFailure, await console.RunAsync(
                [
                    "preflight", "--migration", Guid.CreateVersion7().ToString("D"),
                    "--confirm-maintenance-read-only",
                    "--confirm-restorable-backup",
                    "--confirm-configuration-and-keys",
                    "--confirm-permissions-and-capacity"
                ]));
            AssertSuccess(await console.RunAsync(["status", "--migration", id]));
            AssertSuccess(await console.RunAsync(["create-shadow", "--migration", id]));
            AssertSuccess(await console.RunAsync(["backfill", "--migration", id, "--batch-size", "1"]));
            AssertSuccess(await console.RunAsync(["verify", "--migration", id, "--batch-size", "1"]));

            Assert.Equal((int)IdentityTokenMigrationConsoleExitCode.Usage,
                await console.RunAsync(["cutover", "--migration", id]));
            AssertSuccess(await console.RunAsync(["cutover", "--migration", id, "--confirm-cutover"]));
            Assert.Equal((int)IdentityTokenMigrationConsoleExitCode.MigrationFailure,
                await console.RunAsync(
                    ["accept-writes", "--migration", id, "--confirm-accept-protected-writes"]));

            AssertSuccess(await console.RunAsync(
                ["runtime-verify", "--migration", id, "--batch-size", "1"]));
            AssertSuccess(await console.RunAsync(
                ["accept-writes", "--migration", id, "--confirm-accept-protected-writes"]));
            Assert.Equal((int)IdentityTokenMigrationConsoleExitCode.MigrationFailure,
                await console.RunAsync(["rollback", "--migration", id, "--confirm-rollback"]));

            Assert.Equal((int)IdentityTokenMigrationConsoleExitCode.Usage,
                await console.RunAsync(
                    ["remove-plaintext", "--migration", id, "--confirm-irreversible-removal"]));
            AssertSuccess(await console.RunAsync(
                [
                    "remove-plaintext", "--migration", id,
                    "--confirm-backup-retention-addressed",
                    "--confirm-replicas-exports-addressed",
                    "--confirm-irreversible-removal"
                ]));

            IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint?> loaded =
                await new SqliteIdentityTokenMigrationCheckpointStore(connectionString)
                    .LoadAsync(migrationId, CancellationToken.None);
            Assert.True(loaded.IsSuccess);
            Assert.NotNull(loaded.Value);
            Assert.Equal(IdentityTokenMigrationStage.PlaintextRemoved, loaded.Value.Stage);
            Assert.Equal(0, await CountObjectsAsync(
                connectionString,
                new SqliteIdentityTokenMigrationNames(migrationId).LegacyTable));
            Assert.DoesNotContain("token-secret", output.ToString(), StringComparison.Ordinal);
            Assert.DoesNotContain("token-secret", error.ToString(), StringComparison.Ordinal);
            Assert.DoesNotContain(connectionString, output.ToString(), StringComparison.Ordinal);
            Assert.DoesNotContain(connectionString, error.ToString(), StringComparison.Ordinal);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            File.Delete(databasePath);
        }
    }

    [Fact]
    public async Task Console_RejectsUnknownOptionsAndNonVersion7MigrationIds()
    {
        using StringWriter output = new(CultureInfo.InvariantCulture);
        using StringWriter error = new(CultureInfo.InvariantCulture);
        var console = new SqliteIdentityTokenMigrationConsole(
            "Data Source=:memory:",
            new OperatorProtectionAdapter(),
            new SuccessfulRuntimeVerifier(),
            output,
            error);

        Assert.Equal((int)IdentityTokenMigrationConsoleExitCode.Usage,
            await console.RunAsync(["status", "--migration", Guid.NewGuid().ToString("D")]));
        Assert.Equal((int)IdentityTokenMigrationConsoleExitCode.Usage,
            await console.RunAsync(
                ["status", "--migration", Guid.CreateVersion7().ToString("D"), "--unexpected"]));
    }

    private static void AssertSuccess(int exitCode) =>
        Assert.Equal((int)IdentityTokenMigrationConsoleExitCode.Success, exitCode);

    private static async Task CreateLegacyDatabaseAsync(string connectionString)
    {
        await using SqliteConnection connection = new(connectionString);
        await connection.OpenAsync();
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            "CREATE TABLE \"AspNetUsers\" (\"Id\" TEXT NOT NULL PRIMARY KEY);" +
            "CREATE TABLE \"AspNetUserTokens\" (" +
            "\"UserId\" TEXT NOT NULL, \"LoginProvider\" TEXT NOT NULL, \"Name\" TEXT NOT NULL, \"Value\" TEXT NULL, " +
            "CONSTRAINT \"PK_AspNetUserTokens\" PRIMARY KEY (\"UserId\", \"LoginProvider\", \"Name\"), " +
            "CONSTRAINT \"FK_AspNetUserTokens_AspNetUsers_UserId\" FOREIGN KEY (\"UserId\") " +
            "REFERENCES \"AspNetUsers\" (\"Id\") ON DELETE CASCADE);" +
            "INSERT INTO \"AspNetUsers\" (\"Id\") VALUES ('user-1');" +
            "INSERT INTO \"AspNetUserTokens\" (\"UserId\", \"LoginProvider\", \"Name\", \"Value\") " +
            "VALUES ('user-1', 'provider', 'purpose', 'token-secret');";
        await command.ExecuteNonQueryAsync();
    }

    private static async Task<long> CountObjectsAsync(string connectionString, string objectName)
    {
        await using SqliteConnection connection = new(connectionString);
        await connection.OpenAsync();
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE name = $name";
        command.Parameters.AddWithValue("$name", objectName);
        return Convert.ToInt64(await command.ExecuteScalarAsync(), CultureInfo.InvariantCulture);
    }

    private sealed class SuccessfulRuntimeVerifier : IIdentityTokenMigrationRuntimeVerifier
    {
        public ValueTask<IdentityTokenMigrationResult<int>> VerifyBatchAsync(
            IReadOnlyList<LegacyIdentityTokenMigrationRow> sourceRows,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(IdentityTokenMigrationResult<int>.Success(sourceRows.Count));
    }

    private sealed class OperatorProtectionAdapter : IIdentityTokenMigrationProtectionAdapter
    {
        public IdentityTokenMigrationResult<string> ComputeRoutingHash(LegacyIdentityTokenMigrationRow sourceRow) =>
            IdentityTokenMigrationResult<string>.Success(
                Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
                    sourceRow.UserId + "\0" + sourceRow.LoginProvider + "\0" + sourceRow.Name))));

        public IdentityTokenMigrationResult<ProtectedIdentityTokenMigrationRow> Protect(
            LegacyIdentityTokenMigrationRow sourceRow,
            Guid tokenId,
            string routingHash) =>
            IdentityTokenMigrationResult<ProtectedIdentityTokenMigrationRow>.Success(
                new ProtectedIdentityTokenMigrationRow(
                    tokenId,
                    sourceRow.UserId,
                    Encode(sourceRow.LoginProvider),
                    Encode(sourceRow.Name),
                    sourceRow.Value is null ? null : Encode(sourceRow.Value),
                    routingHash));

        public IdentityTokenMigrationResult<bool> Verify(
            LegacyIdentityTokenMigrationRow sourceRow,
            ProtectedIdentityTokenMigrationRow protectedRow) =>
            IdentityTokenMigrationResult<bool>.Success(
                string.Equals(sourceRow.UserId, protectedRow.UserId, StringComparison.Ordinal) &&
                string.Equals(sourceRow.LoginProvider, Decode(protectedRow.EncryptedLoginProvider), StringComparison.Ordinal) &&
                string.Equals(sourceRow.Name, Decode(protectedRow.EncryptedName), StringComparison.Ordinal) &&
                string.Equals(sourceRow.Value, protectedRow.EncryptedValue is null ? null : Decode(protectedRow.EncryptedValue), StringComparison.Ordinal));

        private static string Encode(string value) =>
            "protected:" + Convert.ToBase64String(Encoding.UTF8.GetBytes(value));

        private static string Decode(string value) =>
            Encoding.UTF8.GetString(Convert.FromBase64String(value["protected:".Length..]));
    }
}

public sealed class OperatorConsoleTestBootstrap : IIdentityTokenMigrationConsoleBootstrap
{
    public static string? ConnectionString { get; set; }

    public static int SessionsCreated { get; private set; }

    public ValueTask<IIdentityTokenMigrationConsoleSession> CreateSessionAsync(
        CancellationToken cancellationToken = default)
    {
        SessionsCreated++;
        return ValueTask.FromResult<IIdentityTokenMigrationConsoleSession>(
            new Session(ConnectionString ?? throw new InvalidOperationException("Test connection is not configured.")));
    }

    public static void Reset()
    {
        ConnectionString = null;
        SessionsCreated = 0;
    }

    private sealed class Session(string connectionString) : IIdentityTokenMigrationConsoleSession
    {
        public string ConnectionString { get; } = connectionString;

        public IIdentityTokenMigrationProtectionAdapter ProtectionAdapter { get; } = new UnusedAdapter();

        public IIdentityTokenMigrationRuntimeVerifier RuntimeVerifier { get; } = new UnusedAdapter();

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class UnusedAdapter :
        IIdentityTokenMigrationProtectionAdapter,
        IIdentityTokenMigrationRuntimeVerifier
    {
        public IdentityTokenMigrationResult<string> ComputeRoutingHash(LegacyIdentityTokenMigrationRow sourceRow) =>
            IdentityTokenMigrationResult<string>.Failure(IdentityTokenMigrationFailureCode.Unknown);

        public IdentityTokenMigrationResult<ProtectedIdentityTokenMigrationRow> Protect(
            LegacyIdentityTokenMigrationRow sourceRow,
            Guid tokenId,
            string routingHash) =>
            IdentityTokenMigrationResult<ProtectedIdentityTokenMigrationRow>.Failure(
                IdentityTokenMigrationFailureCode.Unknown);

        public IdentityTokenMigrationResult<bool> Verify(
            LegacyIdentityTokenMigrationRow sourceRow,
            ProtectedIdentityTokenMigrationRow protectedRow) =>
            IdentityTokenMigrationResult<bool>.Failure(IdentityTokenMigrationFailureCode.Unknown);

        public ValueTask<IdentityTokenMigrationResult<int>> VerifyBatchAsync(
            IReadOnlyList<LegacyIdentityTokenMigrationRow> sourceRows,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(
                IdentityTokenMigrationResult<int>.Failure(IdentityTokenMigrationFailureCode.Unknown));
    }
}
