# Protected ASP.NET Core Identity user-token design

Status: SQLite and PostgreSQL clean-schema integration, benchmarks, migration executors, and provider-selectable operator console implemented  
Baseline: `Microsoft.AspNetCore.Identity.EntityFrameworkCore` 10.0.9  
Target runtime: .NET 11

## Purpose

This document defines the first expansion of `Mrbr.Encryption.Data.Identity` beyond protected user properties. It replaces the default `IdentityUserToken<TKey>` persistence shape with a schema that protects token routing metadata and token values while preserving the `IUserAuthenticationTokenStore<TUser>` behaviour used by `UserManager`.

The default Identity model uses the composite primary key `{ UserId, LoginProvider, Name }`. That key cannot be retained because randomized encryption must not participate in a relational key and the plaintext provider and name must not remain visible.

## Approved decisions

- Use a surrogate `Guid` primary key generated with `Guid.CreateVersion7()`.
- Keep `UserId` plaintext as the Identity user foreign key.
- Encrypt `LoginProvider` and `Name` independently under `IdentityToken`.
- Encrypt `Value` independently under `IdentityCredential`.
- Locate a logical token with one keyed, deterministic composite routing hash under `IdentityTokenLookup`.
- Include `UserId`, `LoginProvider`, and `Name` in that routing hash.
- Build and validate the clean replacement schema first. Migration from Identity's existing token table is a later, explicit project.

UUIDv7 is selected for its time-ordered database insertion characteristics. It is not opaque in the same sense as a random UUID: it encodes a Unix timestamp and therefore reveals approximate record creation time and ordering to anyone who can read the database. No security decision may depend on the identifier being unpredictable.

## Proposed entity and table

The application-owned protected token entity derives from Identity's token entity so it can remain part of a custom `IdentityDbContext` model.

```csharp
public sealed class ApplicationUserToken : IdentityUserToken<string>
{
    public Guid TokenId { get; set; } = Guid.CreateVersion7();

    [Encrypted("IdentityToken")]
    public override string LoginProvider { get; set; } = null!;

    [Encrypted("IdentityToken")]
    public override string Name { get; set; } = null!;

    [Encrypted("IdentityCredential")]
    public override string? Value { get; set; }

    public string RoutingHash { get; set; } = null!;
}
```

The exact generated API may use an Identity-specific type or marker attribute to prevent applications from manually maintaining `RoutingHash`. The source generator, not application business logic, must calculate it.

| Column | Treatment | Constraint |
|---|---|---|
| `TokenId` | Plain UUIDv7 | Primary key; generated in the application with `Guid.CreateVersion7()`. |
| `UserId` | Plain | Required foreign key to the user table and indexed for user-scoped operations. |
| `LoginProvider` | Encrypted string | Required; never queried directly in SQL. |
| `Name` | Encrypted string | Required; never queried directly in SQL. |
| `Value` | Encrypted nullable string | Nullable to preserve the Identity contract; never deterministically hashed. |
| `RoutingHash` | Keyed deterministic HMAC | Required, fixed maximum length, globally unique. |

Including `UserId` in the routing hash prevents equal provider/name pairs belonging to different users from producing the same database value. The database still exposes the number of token rows per user and their approximate creation order.

## Canonical routing input

The HMAC input must be binary, versioned, and unambiguous. It must not be simple string concatenation and must not depend on culture, platform endianness, JSON formatting, or separator characters.

Version 1 is:

1. a four-byte unsigned big-endian domain length followed by the UTF-8 domain `Mrbr.Encryption.Data.Identity/UserTokenRoute`;
2. one byte containing format version `1`;
3. a four-byte unsigned big-endian field count, currently `3`;
4. three fields in the fixed order `UserId`, `LoginProvider`, `Name`;
5. for each field, a four-byte unsigned big-endian length followed by its UTF-8 bytes.

The three values are encoded exactly as supplied to the Identity store. They are protocol identifiers, so the encoder performs no case conversion, trimming, Unicode normalization, or culture-sensitive transformation. Null is invalid for all three routing fields; an empty provider or name is represented by a zero length and remains distinct from null.

The routing service then applies keyed deterministic HMAC using the configured `IdentityTokenLookup` source-key mapping and its stable search-key handle. The implementation should use pooled buffers or incremental hashing to avoid avoidable hot-path allocations and clear temporary plaintext buffers when practical.

Changing any byte of this format is a data migration. A future format must receive a new version and support an intentional read/rewrite transition.

## Store behaviour

The generated store must implement the observable contract of `IUserAuthenticationTokenStore<TUser>` through `SetTokenAsync`, `GetTokenAsync`, and `RemoveTokenAsync`. Authenticator keys, recovery-code records, and ordinary provider tokens use these operations and must pass integration tests.

### Get

1. Validate arguments and cancellation using normal Identity conventions.
2. Compute the composite routing HMAC.
3. Query by the unique `RoutingHash`.
4. If there is no row, return `null`; absence is not a protection failure.
5. Decrypt and ordinally compare `UserId`, `LoginProvider`, and `Name` as applicable.
6. Decrypt and return `Value` only after the candidate has been verified.

A hash match is only a candidate. Authentication failure, malformed ciphertext, missing key material, or a verified mismatch must never be converted into “token not found.”

### Set

1. Compute the routing HMAC and query the existing candidate.
2. Verify any candidate's decrypted provider and name.
3. If verified, replace the independently encrypted `Value` and retain its `TokenId`.
4. Otherwise insert a new row with `TokenId = Guid.CreateVersion7()` and independently encrypted routing fields and value.
5. Treat a unique-index race as a bounded concurrency case: reload, verify, and update once. Do not loop indefinitely and do not overwrite an unverified row.

### Remove

Compute the routing HMAC, verify the decrypted candidate, and delete only the verified row. A missing row remains an idempotent success. A protection or verification failure fails closed.

### Collision and corruption rules

- A routing-HMAC collision that decrypts to different routing fields is a security failure, not a missing token.
- More than one candidate or more than one verified row is an invalid persistence state.
- Tampered ciphertext is reported as an authentication failure and is never skipped.
- The store must not reveal protected plaintext, ciphertext, handles, or full HMAC values in logs or exception messages.

## Result and exception boundary

Internal generated protection and verification helpers should return a dependency-free `ProtectionResult<T>` with a stable `ProtectionFailureCode`. Expected data-plane failures include malformed payload, authentication failure, missing or unavailable key, retired key, unsupported algorithm, hash mismatch, ambiguous match, and bounded persistence conflict.

ASP.NET Core Identity's token-store interface does not provide a result-union return type. The generated store therefore translates a failed internal result into one typed `IdentityDataProtectionException` at that framework boundary. Programming errors, invalid startup configuration, cancellation, and database-provider exceptions remain exceptions. This preserves high-throughput result handling inside the library without silently changing Identity's public semantics.

## EF model and generator requirements

The implementation phase must:

- recognize the custom user-token type from the application's full generic `IdentityDbContext` hierarchy;
- replace Identity's composite token primary key with `TokenId`;
- remove plaintext indexes involving `LoginProvider` or `Name`;
- configure a unique index on `RoutingHash` and an index on `UserId`;
- ensure `TokenId` is generated in application code, not by provider-specific database SQL;
- generate the routing-HMAC calculator and the token-store overrides without runtime reflection;
- generate startup validation for `IdentityToken`, `IdentityTokenLookup`, and `IdentityCredential` source-key mappings;
- reject parameterless protection attributes and any missing source-key mapping;
- prevent direct EF predicates over encrypted token routing properties through analyzer diagnostics.

The generator should emit the exact full-generic Identity store base needed by the selected Identity/EF version. That signature must be confirmed in a compile spike before the public API is frozen.

## Provider requirements

### SQLite

- Store `Guid` using EF Core's normal SQLite mapping.
- Verify UUIDv7 round-trips without changing its value.
- Exercise all token workflows using a real SQLite connection, not only the EF in-memory provider.

### PostgreSQL

- Map `TokenId` to PostgreSQL `uuid`; no database extension is required because the application creates the value.
- Store the fixed HMAC representation in a bounded non-Unicode string column or provider-equivalent binary column selected consistently by the data package.
- Verify index creation, uniqueness races, query plans, and migration SQL.
- Benchmark insert locality against random UUIDs, while keeping the UUIDv7 timestamp disclosure in the security documentation.

## Migration boundary

Version 2's first implementation targets newly created databases. It must not silently alter an existing `AspNetUserTokens` table.

The approved offline migration facility uses an adjacent protected shadow table rather than rewriting plaintext columns in place. It backfills and verifies every row while the source table is read-only, performs an explicit table swap, and only removes the retained plaintext table after an observation period. UUIDv7 values assigned during backfill describe migration order, not original token creation time. The complete contract and rollback boundary are defined in [identity-token-migration-design.md](identity-token-migration-design.md).

## Acceptance tests

- `SetAuthenticationTokenAsync`, `GetAuthenticationTokenAsync`, and `RemoveAuthenticationTokenAsync` round-trip through `UserManager`.
- Authenticator-key reset/read and recovery-code replace/redeem workflows pass.
- Ordinary external-provider token storage passes.
- Re-setting the same logical token retains one row and its original `TokenId`.
- Newly inserted identifiers are RFC 9562 version 7 GUIDs.
- Equal provider/name values for different users produce different routing hashes.
- Structured inputs that would collide under naïve concatenation produce different routing hashes.
- Forced routing-hash collisions fail closed after plaintext verification.
- Missing rows return `null`; malformed or unauthentic ciphertext returns a typed failure at the internal boundary and a typed exception at the Identity boundary.
- Missing source-key configuration prevents application startup.
- Raw SQLite and PostgreSQL inspection reveals no plaintext provider, name, token value, authenticator key, or recovery code.
- SQLite and PostgreSQL concurrency tests prove the unique route invariant.
- Allocation, query-count, candidate-count, and latency benchmarks are recorded before public release.

## Implementation sequence

1. **Implemented:** introduce `ProtectionResult<T>`, failure codes, and the single Identity boundary exception.
2. **Implemented:** add and test the canonical composite routing encoder/HMAC helper.
3. **Implemented:** add the protected token marker/entity contract and source-generator validation.
4. **Implemented:** generate EF model configuration and startup source-key validation.
5. **Implemented:** generate the specialized Identity token-store operations.
6. **Implemented:** run SQLite workflow, raw-database, corrupt-ciphertext, forced-collision and concurrent-insert tests. The concurrency case is repeated during verification to detect timing instability.
7. **Implemented:** add a PostgreSQL 17 integration fixture covering `uuid` mapping, protected raw storage, generated unique/user indexes, indexed routing query plans, and concurrent logical-route insertion.
8. **Implemented:** add a BenchmarkDotNet harness separating identifier, encoding, HMAC, encryption, decryption, candidate-verification, and provider persistence costs. Record representative SQLite and PostgreSQL baselines before freezing the public API.
9. **Implemented:** the separate non-packaged migration projects enforce offline stages, resumable provider-neutral batches, rollback invariants, durable SQLite/PostgreSQL checkpoints, generated application protection and all-row runtime verification, provider-specific shadow/backfill/verification/cutover/rollback execution, a protected-write gate, explicit approved plaintext removal, DDL/checkpoint crash reconciliation, integrity gates, active-batch cancellation/corruption failure behavior, and one-transition-per-command operator execution through an application-owned bootstrap.
