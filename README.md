# Mrbr.Encryption.Data.Identity

Identity integration for `Mrbr.Encryption.Data`, providing collision-safe username, email, role-name, claim, and protected user-token lookup over source-generated keyed deterministic hashes.

The proposed protection policy for the wider Identity schema is recorded in the [ASP.NET Core Identity entity security audit](docs/identity-entity-security-audit.md). The approved next phase is detailed in the [protected Identity user-token design](docs/identity-token-security-design.md), including its UUIDv7 surrogate key and composite keyed lookup.

## Current scope

- ASP.NET Core Identity users and roles with `string`, GUID, integer, or application-defined strongly typed keys.
- Public, provider-neutral, unsealed `EncryptedIdentityUser` and `EncryptedIdentityRole` entities for direct application use or optional consumer inheritance.
- Public protected string-key user-claim and role-claim entities shared by every EF provider.
- A reusable `UserStore` base that delegates username and email searches to source-generated, plaintext-verifying lookups.
- A reusable `RoleStore` base that delegates normalized role-name searches to a source-generated, plaintext-verifying lookup and fails closed on ambiguous verified matches.
- An Entity Framework model helper that removes Identity's plaintext lookup indexes before generated HMAC indexes are added.
- An explicit `[GenerateEncryptedIdentityLookup]` marker used by `Mrbr.Encryption.Data.SourceGenerator` to emit the application-specific lookup adapter.
- An explicit `[GenerateEncryptedIdentityTokenStore("IdentityTokenLookup")]` marker for UUIDv7 token keys, encrypted provider/name/value columns, and composite keyed routing.
- An explicit `[GenerateEncryptedIdentityClaimStores("IdentityLookup")]` marker for encrypted user/role claim contents and owner/type/value composite keyed routing. It composes with the protected token store.
- An explicit `[GenerateEncryptedIdentityLoginStore("IdentityLookup")]` marker for UUIDv7 external-login keys, encrypted provider metadata, and composite provider/key routing.
- An optional `[GenerateEncryptedIdentityTokenMigrationAdapter]` marker, supplied by the non-packaged migration project, that emits the application-bound protection adapter and runtime verifier used for legacy token backfill, pre-cutover verification, and post-cutover Identity reads.
- A non-packaged SQLite/PostgreSQL operator console that loads an application-owned bootstrap and exposes one explicit, acknowledged migration transition per invocation.

The consuming application continues to own its user type, `IdentityDbContext`, source-key attributes, and deployment configuration. This keeps decisions about which Identity properties are sensitive and which key domains protect them explicit.

## Lookup contract

Apply `[GenerateEncryptedIdentityLookup]` to the application's `IdentityDbContext<TUser>`. The source generator verifies that `TUser.NormalizedUserName` and `TUser.NormalizedEmail` are both marked `[Hashed]`, then emits the `IEncryptedIdentityUserLookup<TUser>` implementation and concrete encrypted user store.

After the usual Identity Entity Framework registration, select the marked context:

```csharp
identity.AddEntityFrameworkStores<EncryptionDbContext>();
identity.AddMrbrGeneratedIdentityStore<EncryptionDbContext>();
```

The generated registration installs the collision-verifying user lookup and encrypted user store. When the context's role type protects `NormalizedName` with `[Hashed]`, it also installs the generated role lookup and encrypted role store. `EncryptedIdentityUserStore<TUser, TRole, TContext>` and `EncryptedIdentityRoleStore<TRole, TContext, TUserRole, TRoleClaim>` remain public for applications that deliberately need custom stores.

The store accepts zero or one verified plaintext match. More than one verified match is treated as an invalid security state and throws rather than selecting an arbitrary account.

## Email uniqueness

Both Identity email modes are supported. Declare the database model through the normalized email attribute:

```csharp
[Hashed("IdentityLookup", "IdentityEmail", HashIndexType.NonUnique, DataNormalization.None)]
public override string? NormalizedEmail { get; set; }
```

Select `HashIndexType.Unique` when `IdentityOptions.User.RequireUniqueEmail` is enabled and `HashIndexType.NonUnique` when it is disabled. Generated store registration installs an options validator and enables `ValidateOnStart`; a hosted application fails startup if the runtime option does not match the generated HMAC index. Resolving `IdentityOptions` directly also performs the validation.

Non-unique mode permits multiple accounts to store the same email. Because `FindByEmailAsync` cannot safely select one of several verified accounts, an ambiguous lookup fails closed. Workflows that allow duplicate emails must not treat an email address as an account identifier.

## Model configuration

Call `RemoveIdentityPlaintextLookupIndexes<TUser>()` after `base.OnModelCreating(modelBuilder)` and before `AddMrbrGeneratedEncryption(...)`:

```csharp
protected override void OnModelCreating(ModelBuilder modelBuilder)
{
    base.OnModelCreating(modelBuilder);
    modelBuilder.RemoveIdentityPlaintextLookupIndexes<ApplicationUser>();
    modelBuilder.RemoveIdentityPlaintextRoleLookupIndex<ApplicationRole>();
    modelBuilder.AddMrbrGeneratedEncryption(dataProtectionService, sourceKeyMapConfig);
}
```

The generated unique HMAC indexes then replace Identity's conventional plaintext user and role lookup indexes.

## Security boundary

Database HMAC matches are candidates, not proof of plaintext equality. The lookup implementation must use the generated collision-verifying query methods, which decrypt candidate rows and compare normalized plaintext before returning them.

The package supports provider-neutral encrypted passkeys for new schemas, including independently protected typed fields and a keyed credential route used by generated Identity store operations. Protected users, roles, claims, tokens, external logins, and passkeys work with string, GUID, integer, and explicitly serialized strongly typed identifiers. Migration tooling for existing plaintext role, claim, login, and passkey rows remains future work; existing token rows have explicit non-packaged SQLite and PostgreSQL migration paths.

## Protected claims

Derive the context's claim types from `EncryptedIdentityUserClaim<string>` and `EncryptedIdentityRoleClaim<string>`, override `ClaimType` and `ClaimValue` with `[Encrypted]`, and mark the context with `[GenerateEncryptedIdentityClaimStores("IdentityLookup")]`. Configure their non-unique routing indexes with `ConfigureEncryptedIdentityClaims<TUserClaim, TRoleClaim>()` before `AddMrbrGeneratedEncryption(...)`.

Generated stores compute a domain-separated HMAC over owner ID, claim type, and claim value. Replace and remove operations query that route and decrypt every candidate before mutation; any non-matching collision candidate fails closed. Duplicate identical claims remain valid Identity records. Because owner ID participates in the route, `GetUsersForClaimAsync` deliberately scans and verifies protected claims; applications relying heavily on that global operation need a separately reviewed type/value route.

## PostgreSQL integration tests

Set `MRBR_TEST_POSTGRES_CONNECTION_STRING` to a PostgreSQL account that may create and drop temporary databases, then run the test project. PostgreSQL tests are reported as skipped when the variable is absent.

For a disposable local Docker instance, run `./run-postgresql-tests.ps1` from the repository root. The script starts PostgreSQL 17 on loopback port `55432`, runs only the PostgreSQL integration suite, and always removes the container and volume afterward.

## Performance benchmarks

`Mrbr.Encryption.Data.Identity.Benchmarks` uses BenchmarkDotNet to measure the costs separately:

- UUIDv4 and UUIDv7 generation;
- canonical composite-route encoding and keyed HMAC;
- token encryption and decryption;
- collision-candidate plaintext verification at 1, 8, and 32 candidates;
- a comparable plaintext and protected insert/lookup/delete persistence cycle.

Run `./run-benchmarks.ps1` for the short SQLite suite. Add `-WithPostgreSql` to include a disposable PostgreSQL 17 database, or set `MRBR_TEST_POSTGRES_CONNECTION_STRING` before invoking the benchmark project directly. The PostgreSQL account must be allowed to create and drop temporary databases.

Benchmark results are machine- and runtime-specific evidence, not API performance guarantees. The methodology and recorded baseline are in [performance-baseline.md](docs/performance-baseline.md).

## Existing token database migration

Existing plaintext `AspNetUserTokens` tables are never converted at application startup. Migration is an explicit maintenance operation using a protected shadow table, bounded committed batches, full decrypt-and-compare verification, and a controlled table swap.

`Mrbr.Encryption.Data.Identity.Migration` contains the non-packaged migration checkpoint, state machine, provider-neutral batch coordinator, legacy-reader contract, generated protection/batch-processor contract, and durable checkpoint-store contract. It prevents tooling from skipping preflight or full verification and records the exact point at which new protected writes make a metadata-only rollback unsafe.

`Mrbr.Encryption.Data.Identity.Migration.Sqlite` provides the first provider executor: strict legacy/protected schema validation, protected shadow-table creation, bounded idempotent backfill, full verification, transactional cutover, safe pre-write rollback, durable non-secret SQLite checkpoints, SQLite foreign-key/integrity gates, and retry reconciliation when DDL commits immediately before checkpoint persistence fails. Add `[GenerateEncryptedIdentityTokenMigrationAdapter]` to the already marked application context, then call `services.AddMrbrGeneratedIdentityTokenMigrationAdapter<YourContext>()`. The generated implementation reuses the runtime routing HMAC and exact `SourceKeyMapConfig` encryption domains for provider, name, and value; after cutover it verifies every retained legacy row through the generated EF/Identity lookup before protected writes can be accepted. Retained plaintext removal is a separate, migration-bound operation requiring explicit acknowledgement that backup retention, replicas/exports, and irreversible deletion have been addressed. Real-file failure injection covers active-batch cancellation, resumability, malformed or wrong plaintext, DDL/checkpoint crashes, the runtime write gate, and plaintext-removal reconciliation.

`Mrbr.Encryption.Data.Identity.Migration.PostgreSql` provides the corresponding PostgreSQL 17 executor. It uses native `uuid` token identifiers, bounded transactions, deterministic `COLLATE "C"` source ordering, transaction-scoped advisory locking for checkpoint updates, transactional table/index cutover under explicit table locks, strict catalog validation, and retry reconciliation around committed DDL. Its integration test runs the complete generated-adapter migration against a disposable PostgreSQL database and injects checkpoint failures after cutover and plaintext removal.

`Mrbr.Encryption.Data.Identity.Migration.Console` is the provider-selectable non-interactive operator entry point. It has no `run-all` command, accepts no connection string or key material on its command line, rejects unknown options, and loads deployment configuration plus generated adapters through a consuming-application bootstrap. Preflight, shadow creation, backfill, verification, cutover, runtime verification, write acceptance, rollback, and plaintext removal remain separate invocations with command-specific acknowledgements. See the [operator console README](Mrbr.Encryption.Data.Identity.Migration.Console/README.md). The migration projects remain deliberately non-packaged while operational hardening continues.

See [identity-token-migration-design.md](docs/identity-token-migration-design.md) before attempting to migrate an existing database.
