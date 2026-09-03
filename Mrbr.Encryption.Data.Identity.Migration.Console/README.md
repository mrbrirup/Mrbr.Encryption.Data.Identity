# Mrbr.Encryption.Data.Identity.Migration.Console

This non-packaged executable provides explicit, restartable SQLite and PostgreSQL commands over the protected Identity token migration library. It never creates or replaces keys and never reads connection or key configuration from command-line arguments.

The consuming application supplies a public, parameterless implementation of `IIdentityTokenMigrationConsoleBootstrap`. Its session selects `Sqlite` or `PostgreSql`, returns the externally configured provider connection string, and exposes the generated `IIdentityTokenMigrationProtectionAdapter` and `IIdentityTokenMigrationRuntimeVerifier` resolved from the application's service provider. Keep that service provider and scope alive until the session is disposed.

Select the bootstrap using `--bootstrap-assembly` and `--bootstrap-type`, or the corresponding `MRBR_IDENTITY_MIGRATION_BOOTSTRAP_ASSEMBLY` and `MRBR_IDENTITY_MIGRATION_BOOTSTRAP_TYPE` environment variables. The console loads the application assembly and its adjacent dependencies into the default load context so its generated adapters retain the same contract types as the operator.

The bootstrap normally builds the same service registration as the application, including `AddMrbrGeneratedIdentityTokenMigrationAdapter<TContext>()`, creates an asynchronous scope, and returns a session containing the connection string plus these two scoped services:

```csharp
IIdentityTokenMigrationProtectionAdapter protection =
    scope.ServiceProvider.GetRequiredService<IIdentityTokenMigrationProtectionAdapter>();
IIdentityTokenMigrationRuntimeVerifier verifier =
    scope.ServiceProvider.GetRequiredService<IIdentityTokenMigrationRuntimeVerifier>();
```

The session's `DisposeAsync` must dispose both the scope and its owning service provider. Configuration/startup validation is expected to fail before the session is returned when a required source ID, algorithm, key, or stable search-key handle is absent.

Generate a non-secret migration identifier:

```powershell
dotnet run --project Mrbr.Encryption.Data.Identity.Migration.Console -- new-id
```

An approved preflight invocation has this shape (line breaks are for readability):

```powershell
dotnet run --project Mrbr.Encryption.Data.Identity.Migration.Console -- `
  --bootstrap-assembly C:\path\Application.MigrationBootstrap.dll `
  --bootstrap-type Application.IdentityTokenMigrationBootstrap `
  preflight --migration 00000000-0000-7000-8000-000000000000 `
  --confirm-maintenance-read-only `
  --confirm-restorable-backup `
  --confirm-configuration-and-keys `
  --confirm-permissions-and-capacity
```

Replace the illustrative migration identifier with the value emitted by `new-id`.

The operator deliberately has no `run-all` command. Invoke and inspect these commands one at a time:

1. `preflight`
2. `create-shadow`
3. `backfill`
4. `verify`
5. `cutover`
6. `runtime-verify`
7. `accept-writes`
8. `remove-plaintext` after the chosen observation and retention period

`status` may be used between operations. `rollback` is available only after cutover and before protected writes are accepted. Every command except `new-id` and `help` requires `--migration <UUIDv7>`. Backfill and verification commands accept `--batch-size`; the default is 500.

Irreversible and operational transitions require command-specific `--confirm-*` flags. A rejected invocation prints the complete required flag names. These flags contain no secret, but deployment audit tooling should retain the command identity, operator identity, migration UUID, timestamp, exit code, and change-ticket reference outside this program. The console output itself contains only stable failure codes and non-secret checkpoint values; it never prints the database connection string, keys, handles, ciphertext, hashes, or protected values.
