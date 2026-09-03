using System.Globalization;
using Mrbr.Encryption.Data.Identity.Migration.Sqlite;
using Mrbr.Encryption.Data.Identity.Migration.PostgreSql;

namespace Mrbr.Encryption.Data.Identity.Migration.Console;

/// <summary>Executes exactly one explicit SQLite migration transition per invocation.</summary>
public sealed class SqliteIdentityTokenMigrationConsole
{
    private readonly string _connectionString;
    private readonly IdentityTokenMigrationDatabaseProvider _databaseProvider;
    private readonly IIdentityTokenMigrationProtectionAdapter _protectionAdapter;
    private readonly IIdentityTokenMigrationRuntimeVerifier _runtimeVerifier;
    private readonly TextWriter _output;
    private readonly TextWriter _error;

    /// <summary>Creates an operator command runner using application-configured services.</summary>
    public SqliteIdentityTokenMigrationConsole(
        string connectionString,
        IIdentityTokenMigrationProtectionAdapter protectionAdapter,
        IIdentityTokenMigrationRuntimeVerifier runtimeVerifier,
        TextWriter output,
        TextWriter error) : this(
            IdentityTokenMigrationDatabaseProvider.Sqlite,
            connectionString,
            protectionAdapter,
            runtimeVerifier,
            output,
            error)
    {
    }

    /// <summary>Creates an operator runner for the provider selected by the application bootstrap.</summary>
    public SqliteIdentityTokenMigrationConsole(
        IdentityTokenMigrationDatabaseProvider databaseProvider,
        string connectionString,
        IIdentityTokenMigrationProtectionAdapter protectionAdapter,
        IIdentityTokenMigrationRuntimeVerifier runtimeVerifier,
        TextWriter output,
        TextWriter error)
    {
        if (!Enum.IsDefined(databaseProvider)) throw new ArgumentOutOfRangeException(nameof(databaseProvider));
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        ArgumentNullException.ThrowIfNull(protectionAdapter);
        ArgumentNullException.ThrowIfNull(runtimeVerifier);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);
        _connectionString = connectionString;
        _databaseProvider = databaseProvider;
        _protectionAdapter = protectionAdapter;
        _runtimeVerifier = runtimeVerifier;
        _output = output;
        _error = error;
    }

    /// <summary>Runs one command and returns a stable process exit code.</summary>
    public async ValueTask<int> RunAsync(
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        if (!CommandLine.TryParse(arguments, out CommandLine commandLine, out string? usageError))
        {
            await _error.WriteLineAsync($"usage-error={usageError}").ConfigureAwait(false);
            return (int)IdentityTokenMigrationConsoleExitCode.Usage;
        }

        if (!commandLine.HasOnlyAllowedOptions())
        {
            await _error.WriteLineAsync("usage-error=one or more options are not valid for this command.")
                .ConfigureAwait(false);
            return (int)IdentityTokenMigrationConsoleExitCode.Usage;
        }

        if (commandLine.Command == "help")
        {
            await WriteHelpAsync().ConfigureAwait(false);
            return (int)IdentityTokenMigrationConsoleExitCode.Success;
        }

        if (commandLine.Command == "new-id")
        {
            await _output.WriteLineAsync(Guid.CreateVersion7().ToString("D")).ConfigureAwait(false);
            return (int)IdentityTokenMigrationConsoleExitCode.Success;
        }

        if (!commandLine.TryGetMigrationId(out Guid migrationId))
        {
            await _error.WriteLineAsync("usage-error=--migration must contain a UUIDv7 value.").ConfigureAwait(false);
            return (int)IdentityTokenMigrationConsoleExitCode.Usage;
        }

        try
        {
            return commandLine.Command switch
            {
                "status" => await StatusAsync(migrationId, cancellationToken).ConfigureAwait(false),
                "preflight" => await PreflightAsync(commandLine, migrationId, cancellationToken).ConfigureAwait(false),
                "create-shadow" => await CreateShadowAsync(migrationId, cancellationToken).ConfigureAwait(false),
                "backfill" => await BackfillAsync(commandLine, migrationId, cancellationToken).ConfigureAwait(false),
                "verify" => await VerifyAsync(commandLine, migrationId, cancellationToken).ConfigureAwait(false),
                "cutover" => await CutoverAsync(commandLine, migrationId, cancellationToken).ConfigureAwait(false),
                "runtime-verify" => await RuntimeVerifyAsync(commandLine, migrationId, cancellationToken).ConfigureAwait(false),
                "accept-writes" => await AcceptWritesAsync(commandLine, migrationId, cancellationToken).ConfigureAwait(false),
                "rollback" => await RollbackAsync(commandLine, migrationId, cancellationToken).ConfigureAwait(false),
                "remove-plaintext" => await RemovePlaintextAsync(commandLine, migrationId, cancellationToken).ConfigureAwait(false),
                _ => await UnknownCommandAsync(commandLine.Command).ConfigureAwait(false)
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            await _error.WriteLineAsync("cancelled=true").ConfigureAwait(false);
            return (int)IdentityTokenMigrationConsoleExitCode.Cancelled;
        }
    }

    private async ValueTask<int> StatusAsync(Guid migrationId, CancellationToken cancellationToken)
    {
        IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint?> loaded =
            await CheckpointReader.LoadAsync(migrationId, cancellationToken).ConfigureAwait(false);
        if (!loaded.IsSuccess)
        {
            return await WriteFailureAsync(loaded.FailureCode).ConfigureAwait(false);
        }

        if (loaded.Value is null)
        {
            await _error.WriteLineAsync($"migration={migrationId:D} status=not-found").ConfigureAwait(false);
            return (int)IdentityTokenMigrationConsoleExitCode.MigrationNotFound;
        }

        await WriteCheckpointAsync(loaded.Value).ConfigureAwait(false);
        return (int)IdentityTokenMigrationConsoleExitCode.Success;
    }

    private async ValueTask<int> PreflightAsync(
        CommandLine commandLine,
        Guid migrationId,
        CancellationToken cancellationToken)
    {
        string[] approvals =
        [
            "confirm-maintenance-read-only",
            "confirm-restorable-backup",
            "confirm-configuration-and-keys",
            "confirm-permissions-and-capacity"
        ];
        if (!commandLine.HasEveryFlag(approvals))
        {
            return await ApprovalRequiredAsync(approvals).ConfigureAwait(false);
        }

        IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint?> existing =
            await CheckpointReader.LoadAsync(migrationId, cancellationToken).ConfigureAwait(false);
        if (!existing.IsSuccess)
        {
            return await WriteFailureAsync(existing.FailureCode).ConfigureAwait(false);
        }

        if (existing.Value is not null)
        {
            return await WriteFailureAsync(IdentityTokenMigrationFailureCode.InvalidStageTransition)
                .ConfigureAwait(false);
        }

        IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint?> active =
            await LoadActiveAsync(cancellationToken).ConfigureAwait(false);
        if (!active.IsSuccess)
        {
            return await WriteFailureAsync(active.FailureCode).ConfigureAwait(false);
        }

        if (active.Value is not null)
        {
            return await WriteFailureAsync(IdentityTokenMigrationFailureCode.InvalidStageTransition)
                .ConfigureAwait(false);
        }

        IdentityTokenMigrationResult<long> validation = await ValidatePreflightAsync(migrationId, cancellationToken)
            .ConfigureAwait(false);
        if (!validation.IsSuccess)
        {
            return await WriteFailureAsync(validation.FailureCode).ConfigureAwait(false);
        }

        IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint> created =
            IdentityTokenMigrationStateMachine.Create(migrationId, validation.Value);
        if (!created.IsSuccess)
        {
            return await WriteFailureAsync(created.FailureCode).ConfigureAwait(false);
        }

        IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint> passed =
            IdentityTokenMigrationStateMachine.Advance(
                created.Value,
                IdentityTokenMigrationStage.PreflightPassed,
                0,
                0,
                0);
        if (!passed.IsSuccess)
        {
            return await WriteFailureAsync(passed.FailureCode).ConfigureAwait(false);
        }

        await CheckpointStore.SaveAsync(passed.Value, cancellationToken).ConfigureAwait(false);
        return await WriteSuccessAsync(passed.Value).ConfigureAwait(false);
    }

    private async ValueTask<int> CreateShadowAsync(Guid migrationId, CancellationToken cancellationToken)
    {
        IdentityTokenMigrationCheckpoint? checkpoint = await LoadRequiredAsync(migrationId, cancellationToken)
            .ConfigureAwait(false);
        if (checkpoint is null)
        {
            return (int)IdentityTokenMigrationConsoleExitCode.MigrationNotFound;
        }

        return await CompleteAsync(
            await CreateShadowSchemaAsync(checkpoint, cancellationToken).ConfigureAwait(false))
            .ConfigureAwait(false);
    }

    private async ValueTask<int> BackfillAsync(
        CommandLine commandLine,
        Guid migrationId,
        CancellationToken cancellationToken)
    {
        if (!commandLine.TryGetBatchSize(out int batchSize))
        {
            return await BatchSizeUsageAsync().ConfigureAwait(false);
        }

        IdentityTokenMigrationCheckpoint? checkpoint = await LoadRequiredAsync(migrationId, cancellationToken)
            .ConfigureAwait(false);
        if (checkpoint is null)
        {
            return (int)IdentityTokenMigrationConsoleExitCode.MigrationNotFound;
        }

        if (checkpoint.Stage == IdentityTokenMigrationStage.ShadowSchemaCreated)
        {
            IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint> started =
                IdentityTokenMigrationStateMachine.Advance(
                    checkpoint,
                    IdentityTokenMigrationStage.BackfillInProgress,
                    0,
                    0,
                    0);
            if (!started.IsSuccess)
            {
                return await WriteFailureAsync(started.FailureCode).ConfigureAwait(false);
            }

            checkpoint = started.Value;
            await CheckpointStore.SaveAsync(checkpoint, cancellationToken).ConfigureAwait(false);
        }

        IIdentityTokenMigrationSource source = CreateSource(migrationId, retained: false);
        IIdentityTokenMigrationBatchProcessor processor = CreateProcessor(migrationId);
        return await CompleteAsync(await IdentityTokenMigrationCoordinator.BackfillAsync(
            checkpoint,
            source,
            processor,
            CheckpointStore,
            new IdentityTokenMigrationOptions { BatchSize = batchSize },
            cancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
    }

    private async ValueTask<int> VerifyAsync(
        CommandLine commandLine,
        Guid migrationId,
        CancellationToken cancellationToken)
    {
        if (!commandLine.TryGetBatchSize(out int batchSize))
        {
            return await BatchSizeUsageAsync().ConfigureAwait(false);
        }

        IdentityTokenMigrationCheckpoint? checkpoint = await LoadRequiredAsync(migrationId, cancellationToken)
            .ConfigureAwait(false);
        if (checkpoint is null)
        {
            return (int)IdentityTokenMigrationConsoleExitCode.MigrationNotFound;
        }

        IIdentityTokenMigrationSource source = CreateSource(migrationId, retained: false);
        IIdentityTokenMigrationBatchProcessor processor = CreateProcessor(migrationId);
        return await CompleteAsync(await IdentityTokenMigrationCoordinator.VerifyAsync(
            checkpoint,
            source,
            processor,
            CheckpointStore,
            new IdentityTokenMigrationOptions { BatchSize = batchSize },
            cancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
    }

    private async ValueTask<int> CutoverAsync(
        CommandLine commandLine,
        Guid migrationId,
        CancellationToken cancellationToken)
    {
        if (!commandLine.HasFlag("confirm-cutover"))
        {
            return await ApprovalRequiredAsync(["confirm-cutover"]).ConfigureAwait(false);
        }

        IdentityTokenMigrationCheckpoint? checkpoint = await LoadRequiredAsync(migrationId, cancellationToken)
            .ConfigureAwait(false);
        if (checkpoint is null)
        {
            return (int)IdentityTokenMigrationConsoleExitCode.MigrationNotFound;
        }

        return await CompleteAsync(
            await CutoverSchemaAsync(checkpoint, cancellationToken).ConfigureAwait(false))
            .ConfigureAwait(false);
    }

    private async ValueTask<int> RuntimeVerifyAsync(
        CommandLine commandLine,
        Guid migrationId,
        CancellationToken cancellationToken)
    {
        if (!commandLine.TryGetBatchSize(out int batchSize))
        {
            return await BatchSizeUsageAsync().ConfigureAwait(false);
        }

        IdentityTokenMigrationCheckpoint? checkpoint = await LoadRequiredAsync(migrationId, cancellationToken)
            .ConfigureAwait(false);
        if (checkpoint is null)
        {
            return (int)IdentityTokenMigrationConsoleExitCode.MigrationNotFound;
        }

        IIdentityTokenMigrationSource source = CreateSource(migrationId, retained: true);
        return await CompleteAsync(await IdentityTokenMigrationCoordinator.VerifyRuntimeStoreAsync(
            checkpoint,
            source,
            _runtimeVerifier,
            CheckpointStore,
            new IdentityTokenMigrationOptions { BatchSize = batchSize },
            cancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
    }

    private async ValueTask<int> AcceptWritesAsync(
        CommandLine commandLine,
        Guid migrationId,
        CancellationToken cancellationToken)
    {
        if (!commandLine.HasFlag("confirm-accept-protected-writes"))
        {
            return await ApprovalRequiredAsync(["confirm-accept-protected-writes"]).ConfigureAwait(false);
        }

        IdentityTokenMigrationCheckpoint? checkpoint = await LoadRequiredAsync(migrationId, cancellationToken)
            .ConfigureAwait(false);
        if (checkpoint is null)
        {
            return (int)IdentityTokenMigrationConsoleExitCode.MigrationNotFound;
        }

        return await CompleteAsync(await IdentityTokenMigrationCoordinator.AcceptProtectedWritesAsync(
            checkpoint,
            CheckpointStore,
            cancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
    }

    private async ValueTask<int> RollbackAsync(
        CommandLine commandLine,
        Guid migrationId,
        CancellationToken cancellationToken)
    {
        if (!commandLine.HasFlag("confirm-rollback"))
        {
            return await ApprovalRequiredAsync(["confirm-rollback"]).ConfigureAwait(false);
        }

        IdentityTokenMigrationCheckpoint? checkpoint = await LoadRequiredAsync(migrationId, cancellationToken)
            .ConfigureAwait(false);
        if (checkpoint is null)
        {
            return (int)IdentityTokenMigrationConsoleExitCode.MigrationNotFound;
        }

        return await CompleteAsync(
            await RollbackSchemaAsync(checkpoint, cancellationToken).ConfigureAwait(false))
            .ConfigureAwait(false);
    }

    private async ValueTask<int> RemovePlaintextAsync(
        CommandLine commandLine,
        Guid migrationId,
        CancellationToken cancellationToken)
    {
        string[] approvals =
        [
            "confirm-backup-retention-addressed",
            "confirm-replicas-exports-addressed",
            "confirm-irreversible-removal"
        ];
        if (!commandLine.HasEveryFlag(approvals))
        {
            return await ApprovalRequiredAsync(approvals).ConfigureAwait(false);
        }

        IdentityTokenMigrationCheckpoint? checkpoint = await LoadRequiredAsync(migrationId, cancellationToken)
            .ConfigureAwait(false);
        if (checkpoint is null)
        {
            return (int)IdentityTokenMigrationConsoleExitCode.MigrationNotFound;
        }

        var approval = new IdentityTokenMigrationPlaintextRemovalApproval(
            migrationId,
            backupRetentionAddressed: true,
            replicasAndExportsAddressed: true,
            irreversibleRemovalApproved: true);
        return await CompleteAsync(await RemovePlaintextSchemaAsync(
            checkpoint, approval, cancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
    }

    private IIdentityTokenMigrationCheckpointStore CheckpointStore => _databaseProvider switch
    {
        IdentityTokenMigrationDatabaseProvider.Sqlite => new SqliteIdentityTokenMigrationCheckpointStore(_connectionString),
        IdentityTokenMigrationDatabaseProvider.PostgreSql => new PostgreSqlIdentityTokenMigrationCheckpointStore(_connectionString),
        _ => throw new InvalidOperationException("Unsupported migration database provider.")
    };

    private IIdentityTokenMigrationCheckpointReader CheckpointReader =>
        (IIdentityTokenMigrationCheckpointReader)CheckpointStore;

    private ValueTask<IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint?>> LoadActiveAsync(
        CancellationToken cancellationToken) => _databaseProvider switch
        {
            IdentityTokenMigrationDatabaseProvider.Sqlite =>
                new SqliteIdentityTokenMigrationCheckpointStore(_connectionString).LoadActiveAsync(cancellationToken),
            IdentityTokenMigrationDatabaseProvider.PostgreSql =>
                new PostgreSqlIdentityTokenMigrationCheckpointStore(_connectionString).LoadActiveAsync(cancellationToken),
            _ => throw new InvalidOperationException("Unsupported migration database provider.")
        };

    private ValueTask<IdentityTokenMigrationResult<long>> ValidatePreflightAsync(
        Guid migrationId,
        CancellationToken cancellationToken) => _databaseProvider switch
        {
            IdentityTokenMigrationDatabaseProvider.Sqlite =>
                new SqliteIdentityTokenMigrationSchemaExecutor(_connectionString, migrationId)
                    .ValidatePreflightAsync(cancellationToken),
            IdentityTokenMigrationDatabaseProvider.PostgreSql =>
                new PostgreSqlIdentityTokenMigrationSchemaExecutor(_connectionString, migrationId)
                    .ValidatePreflightAsync(cancellationToken),
            _ => throw new InvalidOperationException("Unsupported migration database provider.")
        };

    private ValueTask<IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint>> CreateShadowSchemaAsync(
        IdentityTokenMigrationCheckpoint checkpoint,
        CancellationToken cancellationToken) => _databaseProvider switch
        {
            IdentityTokenMigrationDatabaseProvider.Sqlite =>
                new SqliteIdentityTokenMigrationSchemaExecutor(_connectionString, checkpoint.MigrationId)
                    .CreateShadowSchemaAsync(checkpoint, CheckpointStore, cancellationToken),
            IdentityTokenMigrationDatabaseProvider.PostgreSql =>
                new PostgreSqlIdentityTokenMigrationSchemaExecutor(_connectionString, checkpoint.MigrationId)
                    .CreateShadowSchemaAsync(checkpoint, CheckpointStore, cancellationToken),
            _ => throw new InvalidOperationException("Unsupported migration database provider.")
        };

    private IIdentityTokenMigrationSource CreateSource(Guid migrationId, bool retained) =>
        _databaseProvider switch
        {
            IdentityTokenMigrationDatabaseProvider.Sqlite => retained
                ? new SqliteIdentityTokenMigrationSource(_connectionString, migrationId)
                : new SqliteIdentityTokenMigrationSource(_connectionString),
            IdentityTokenMigrationDatabaseProvider.PostgreSql => retained
                ? new PostgreSqlIdentityTokenMigrationSource(_connectionString, migrationId)
                : new PostgreSqlIdentityTokenMigrationSource(_connectionString),
            _ => throw new InvalidOperationException("Unsupported migration database provider.")
        };

    private IIdentityTokenMigrationBatchProcessor CreateProcessor(Guid migrationId) =>
        _databaseProvider switch
        {
            IdentityTokenMigrationDatabaseProvider.Sqlite =>
                new SqliteIdentityTokenMigrationBatchProcessor(_connectionString, migrationId, _protectionAdapter),
            IdentityTokenMigrationDatabaseProvider.PostgreSql =>
                new PostgreSqlIdentityTokenMigrationBatchProcessor(_connectionString, migrationId, _protectionAdapter),
            _ => throw new InvalidOperationException("Unsupported migration database provider.")
        };

    private ValueTask<IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint>> CutoverSchemaAsync(
        IdentityTokenMigrationCheckpoint checkpoint,
        CancellationToken cancellationToken) => _databaseProvider switch
        {
            IdentityTokenMigrationDatabaseProvider.Sqlite =>
                new SqliteIdentityTokenMigrationSchemaExecutor(_connectionString, checkpoint.MigrationId)
                    .CutoverAsync(checkpoint, CheckpointStore, cancellationToken),
            IdentityTokenMigrationDatabaseProvider.PostgreSql =>
                new PostgreSqlIdentityTokenMigrationSchemaExecutor(_connectionString, checkpoint.MigrationId)
                    .CutoverAsync(checkpoint, CheckpointStore, cancellationToken),
            _ => throw new InvalidOperationException("Unsupported migration database provider.")
        };

    private ValueTask<IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint>> RollbackSchemaAsync(
        IdentityTokenMigrationCheckpoint checkpoint,
        CancellationToken cancellationToken) => _databaseProvider switch
        {
            IdentityTokenMigrationDatabaseProvider.Sqlite =>
                new SqliteIdentityTokenMigrationSchemaExecutor(_connectionString, checkpoint.MigrationId)
                    .RollbackCutoverAsync(checkpoint, CheckpointStore, cancellationToken),
            IdentityTokenMigrationDatabaseProvider.PostgreSql =>
                new PostgreSqlIdentityTokenMigrationSchemaExecutor(_connectionString, checkpoint.MigrationId)
                    .RollbackCutoverAsync(checkpoint, CheckpointStore, cancellationToken),
            _ => throw new InvalidOperationException("Unsupported migration database provider.")
        };

    private ValueTask<IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint>> RemovePlaintextSchemaAsync(
        IdentityTokenMigrationCheckpoint checkpoint,
        IdentityTokenMigrationPlaintextRemovalApproval approval,
        CancellationToken cancellationToken) => _databaseProvider switch
        {
            IdentityTokenMigrationDatabaseProvider.Sqlite =>
                new SqliteIdentityTokenMigrationSchemaExecutor(_connectionString, checkpoint.MigrationId)
                    .RemoveRetainedPlaintextAsync(checkpoint, approval, CheckpointStore, cancellationToken),
            IdentityTokenMigrationDatabaseProvider.PostgreSql =>
                new PostgreSqlIdentityTokenMigrationSchemaExecutor(_connectionString, checkpoint.MigrationId)
                    .RemoveRetainedPlaintextAsync(checkpoint, approval, CheckpointStore, cancellationToken),
            _ => throw new InvalidOperationException("Unsupported migration database provider.")
        };

    private async ValueTask<IdentityTokenMigrationCheckpoint?> LoadRequiredAsync(
        Guid migrationId,
        CancellationToken cancellationToken)
    {
        IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint?> loaded =
            await CheckpointReader.LoadAsync(migrationId, cancellationToken).ConfigureAwait(false);
        if (!loaded.IsSuccess)
        {
            await WriteFailureAsync(loaded.FailureCode).ConfigureAwait(false);
            return null;
        }

        if (loaded.Value is null)
        {
            await _error.WriteLineAsync($"migration={migrationId:D} status=not-found").ConfigureAwait(false);
        }

        return loaded.Value;
    }

    private async ValueTask<int> CompleteAsync(
        IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint> result)
    {
        if (!result.IsSuccess)
        {
            return await WriteFailureAsync(result.FailureCode).ConfigureAwait(false);
        }

        return await WriteSuccessAsync(result.Value).ConfigureAwait(false);
    }

    private async ValueTask<int> WriteSuccessAsync(IdentityTokenMigrationCheckpoint checkpoint)
    {
        await _output.WriteLineAsync("result=success").ConfigureAwait(false);
        await WriteCheckpointAsync(checkpoint).ConfigureAwait(false);
        return (int)IdentityTokenMigrationConsoleExitCode.Success;
    }

    private async ValueTask WriteCheckpointAsync(IdentityTokenMigrationCheckpoint checkpoint) =>
        await _output.WriteLineAsync(
            $"migration={checkpoint.MigrationId:D} stage={checkpoint.Stage} " +
            $"expected={checkpoint.ExpectedSourceRows.ToString(CultureInfo.InvariantCulture)} " +
            $"scanned={checkpoint.SourceRowsScanned.ToString(CultureInfo.InvariantCulture)} " +
            $"ready={checkpoint.TargetRowsReady.ToString(CultureInfo.InvariantCulture)} " +
            $"verified={checkpoint.TargetRowsVerified.ToString(CultureInfo.InvariantCulture)} " +
            $"protected-writes-accepted={checkpoint.ProtectedWritesAccepted.ToString().ToLowerInvariant()}")
            .ConfigureAwait(false);

    private async ValueTask<int> WriteFailureAsync(IdentityTokenMigrationFailureCode failureCode)
    {
        await _error.WriteLineAsync($"result=failure code={failureCode}").ConfigureAwait(false);
        return (int)IdentityTokenMigrationConsoleExitCode.MigrationFailure;
    }

    private async ValueTask<int> ApprovalRequiredAsync(IEnumerable<string> approvals)
    {
        await _error.WriteLineAsync(
            "usage-error=explicit acknowledgement required: " +
            string.Join(' ', approvals.Select(static value => "--" + value))).ConfigureAwait(false);
        return (int)IdentityTokenMigrationConsoleExitCode.Usage;
    }

    private async ValueTask<int> BatchSizeUsageAsync()
    {
        await _error.WriteLineAsync(
            $"usage-error=--batch-size must be 1..{IdentityTokenMigrationOptions.MaximumBatchSize}.")
            .ConfigureAwait(false);
        return (int)IdentityTokenMigrationConsoleExitCode.Usage;
    }

    private async ValueTask<int> UnknownCommandAsync(string command)
    {
        await _error.WriteLineAsync($"usage-error=unknown command '{command}'.").ConfigureAwait(false);
        return (int)IdentityTokenMigrationConsoleExitCode.Usage;
    }

    private async ValueTask WriteHelpAsync() => await _output.WriteLineAsync(
        "Commands: new-id | status | preflight | create-shadow | backfill | verify | cutover | " +
        "runtime-verify | accept-writes | rollback | remove-plaintext\n" +
        "Every migration command requires --migration <UUIDv7>. Batch commands accept --batch-size <1..10000>.\n" +
        "Use the command-specific --confirm-* acknowledgements shown by a rejected command.")
        .ConfigureAwait(false);

    private sealed class CommandLine
    {
        private readonly Dictionary<string, string?> _options;

        private CommandLine(string command, Dictionary<string, string?> options)
        {
            Command = command;
            _options = options;
        }

        public string Command { get; }

        public bool HasFlag(string name) => _options.TryGetValue(name, out string? value) && value is null;

        public bool HasEveryFlag(IEnumerable<string> names) => names.All(HasFlag);

        public bool HasOnlyAllowedOptions()
        {
            string[] allowed = Command switch
            {
                "help" or "new-id" => [],
                "status" or "create-shadow" => ["migration"],
                "preflight" =>
                [
                    "migration",
                    "confirm-maintenance-read-only",
                    "confirm-restorable-backup",
                    "confirm-configuration-and-keys",
                    "confirm-permissions-and-capacity"
                ],
                "backfill" or "verify" or "runtime-verify" => ["migration", "batch-size"],
                "cutover" => ["migration", "confirm-cutover"],
                "accept-writes" => ["migration", "confirm-accept-protected-writes"],
                "rollback" => ["migration", "confirm-rollback"],
                "remove-plaintext" =>
                [
                    "migration",
                    "confirm-backup-retention-addressed",
                    "confirm-replicas-exports-addressed",
                    "confirm-irreversible-removal"
                ],
                _ => []
            };
            return _options.Keys.All(name => allowed.Contains(name, StringComparer.Ordinal));
        }

        public bool TryGetMigrationId(out Guid migrationId)
        {
            migrationId = default;
            return _options.TryGetValue("migration", out string? text) &&
                Guid.TryParseExact(text, "D", out migrationId) &&
                migrationId.Version == 7;
        }

        public bool TryGetBatchSize(out int batchSize)
        {
            batchSize = IdentityTokenMigrationOptions.DefaultBatchSize;
            return !_options.TryGetValue("batch-size", out string? text) ||
                int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out batchSize) &&
                batchSize is > 0 and <= IdentityTokenMigrationOptions.MaximumBatchSize;
        }

        public static bool TryParse(
            IReadOnlyList<string> arguments,
            out CommandLine commandLine,
            out string? error)
        {
            commandLine = null!;
            error = null;
            if (arguments.Count == 0)
            {
                error = "A command is required. Use help.";
                return false;
            }

            string command = arguments[0].ToLowerInvariant();
            var options = new Dictionary<string, string?>(StringComparer.Ordinal);
            for (int index = 1; index < arguments.Count; index++)
            {
                string token = arguments[index];
                if (!token.StartsWith("--", StringComparison.Ordinal) || token.Length == 2)
                {
                    error = "Options must use --name syntax.";
                    return false;
                }

                string name = token[2..];
                if (!options.TryAdd(name, null))
                {
                    error = $"Duplicate option --{name}.";
                    return false;
                }

                if (name is "migration" or "batch-size")
                {
                    if (++index >= arguments.Count || arguments[index].StartsWith("--", StringComparison.Ordinal))
                    {
                        error = $"Option --{name} requires a value.";
                        return false;
                    }

                    options[name] = arguments[index];
                }
            }

            commandLine = new CommandLine(command, options);
            return true;
        }
    }
}
