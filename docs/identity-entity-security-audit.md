# ASP.NET Core Identity entity security audit

Status: active security design; user, token, role, claim, and new-schema external-login runtime phases implemented
Baseline: `Microsoft.AspNetCore.Identity.EntityFrameworkCore` 10.0.9  
Target runtime: .NET 11

## Purpose

This document decides how `Mrbr.Encryption.Data.Identity` should protect the standard ASP.NET Core Identity persistence model before support is expanded beyond `IdentityUser`.

The baseline model contains users, roles, user-role links, user claims, role claims, external logins, user tokens, and passkeys. Identity permits applications to replace each CLR entity type through the generic `IdentityDbContext` hierarchy, so the implementation should use explicit derived entities rather than modifying Microsoft types implicitly. See Microsoft's [Identity model customization guidance](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/customize-identity-model?view=aspnetcore-10.0).

This is a design audit. The implementation-order section records which recommendations are implemented and which remain proposed.

## Threat model and boundaries

The primary scenario is an attacker who obtains a readable copy of the application database but does not possess the external KeyManager configuration or source-key material.

The design should:

- prevent database-only recovery of PII, password verifiers, security stamps, tokens, claim contents, and external-provider identifiers;
- use a fresh encryption key per datum through the existing `{handle}:{cipher}` format;
- use keyed deterministic hashes only where equality lookup or uniqueness is required;
- treat hash matches as candidates and verify decrypted plaintext before returning an entity;
- leave relational primary and foreign keys usable by EF and Identity;
- fail application startup when required algorithms, source IDs, or stable search-key handles are absent;
- keep key replacement and data re-encryption outside normal application startup.

This design does not protect against a compromised application process that can call the configured KeyManager. It also does not hide table shape, row counts, relationships, ciphertext length, repeated keyed-hash values, access patterns, or unencrypted operational metadata. AEAD detects modification of an individual encrypted value, but it does not by itself prevent deletion, replay of an older valid ciphertext, or rollback of the database.

## Treatment vocabulary

| Treatment | Meaning |
|---|---|
| Plain | Deliberately left unencrypted for relational, concurrency, or operational behaviour. |
| Encrypt | Randomized per-datum encryption; no database equality search. |
| Hash | Keyed deterministic HMAC used for lookup; normally paired with encrypted source data. |
| Encrypt + hash | Encrypted source value plus a generated HMAC search column, followed by plaintext collision verification. |
| Redesign | The default Identity key or query shape prevents safe attribute-only protection; custom entities, schema, and store methods are required. |

## Recommended key domains

Do not put every Identity value under the existing `PII` source. Separate logical domains limit the effect of a compromised or retired key and make recovery scope explicit.

| Source key | Intended data |
|---|---|
| `IdentityPII` | Usernames, email addresses, phone numbers and display names. |
| `IdentityLookup` | Stable HMAC keys for normalized username, normalized email, role, claim and provider lookup fields. |
| `IdentityCredential` | Password hashes, security stamps, authenticator secrets, recovery codes and token values. |
| `IdentityAuthorization` | Role names and claim types/values. |
| `IdentityExternalLogin` | External provider keys and associated display information. |
| `IdentityPasskey` | Passkey credential identifiers, public-key records and attestation metadata. |

Encryption and hashing attributes on one property may use different source keys. For example, `NormalizedEmail` can use `IdentityPII` for encryption and `IdentityLookup` for its HMAC.

## Approved policy decisions

- Support both `RequireUniqueEmail = true` and `false`. The generated email HMAC index and Identity option must agree; startup validation should reject an inconsistent combination.
- Treat role names and claim names/values as confidential by default. Their small, enumerable vocabularies make unkeyed hashes especially unsuitable. Keyed HMAC prevents a database-only attacker from testing guesses without the external key, although equality frequency remains visible.
- Encrypt token provider and token name metadata and add keyed hashes for routing. They must not remain permanently plaintext merely because their value sets are small.
- Use application-generated RFC 9562 UUIDv7 values as protected token surrogate primary keys. This improves insertion locality but exposes approximate creation time and ordering; identifiers must not be treated as unpredictable secrets.
- Protect each passkey field separately rather than serializing all `IdentityPasskeyData` into one encrypted blob. The data layer now provides versioned typed encodings for this provider-neutral passkey representation.
- Use PostgreSQL as the second integration-test provider after SQLite.

## Entity audit

### Users (`IdentityUser<TKey>` / `AspNetUsers`)

The current package already protects the string fields listed below and replaces username/email queries with generated collision-verifying lookups.

| Property | Treatment | Reason and implementation requirement |
|---|---|---|
| `Id` | Plain | Primary and foreign-key target. Prefer a random opaque identifier such as a GUID rather than a meaningful value. |
| `UserName` | Encrypt | PII displayed to the user; normal Identity lookup uses `NormalizedUserName`. |
| `NormalizedUserName` | Encrypt + hash | Required login lookup. HMAC index should be unique. |
| `Email` | Encrypt | PII displayed and used for messaging. |
| `NormalizedEmail` | Encrypt + hash | Required email lookup. Support a unique HMAC index when `RequireUniqueEmail` is enabled and a non-unique index when disabled. In non-unique mode, multiple verified email matches must follow Identity-compatible behaviour rather than being silently resolved to one account. |
| `EmailConfirmed` | Plain | Operational Boolean required without a string converter. It reveals account state but not the address. |
| `PasswordHash` | Encrypt | A password verifier remains security-sensitive even though it is already a one-way password hash. Never add a deterministic search hash. |
| `SecurityStamp` | Encrypt | Security-sensitive revocation value. Never searchable. Regeneration must continue to invalidate existing sign-ins. |
| `ConcurrencyStamp` | Plain | EF optimistic-concurrency token. Encryption would change on every save and defeat concurrency comparison. |
| `PhoneNumber` | Encrypt | PII; normally retrieved through the user rather than searched globally. |
| `PhoneNumberConfirmed` | Plain | Operational Boolean; reveals account state. |
| `TwoFactorEnabled` | Plain initially | Operational Boolean. Protecting it requires non-string support and careful update testing. |
| `LockoutEnd` | Plain initially | Needed for lockout decisions and time comparison. Encryption would require typed conversion and may prevent server-side queries. |
| `LockoutEnabled` | Plain | Operational Boolean. |
| `AccessFailedCount` | Plain | Mutable counter used during authentication. Database write integrity and atomic updates matter more than confidentiality. |

Residual risk: the plaintext status fields reveal whether an account exists, uses MFA, is confirmed, or is locked if a row can be associated with a person through external information.

### Roles (`IdentityRole<TKey>` / `AspNetRoles`)

| Property | Treatment | Reason and implementation requirement |
|---|---|---|
| `Id` | Plain | Primary key and user-role foreign-key target. Use an opaque value. |
| `Name` | Encrypt | Role names can reveal authorization policy and organisational structure. |
| `NormalizedName` | Encrypt + hash | `RoleManager.FindByNameAsync` requires equality lookup and uniqueness. Requires a generated encrypted role store and replacement of `RoleNameIndex`. |
| `ConcurrencyStamp` | Plain | Optimistic concurrency token. |

Encrypting role names does not hide role membership: the user-role link table still exposes which opaque users share an opaque role identifier.

Role and claim names are confidential in the default profile. Common names such as `User` and `Admin` have extremely low entropy; deployment-specific names can reduce obvious semantic leakage elsewhere, but they are not a substitute for encryption and keyed hashing.

### User-role links (`IdentityUserRole<TKey>` / `AspNetUserRoles`)

| Property | Treatment | Reason and implementation requirement |
|---|---|---|
| `UserId` | Plain | Composite primary key and foreign key. |
| `RoleId` | Plain | Composite primary key and foreign key. |

There is no payload to encrypt. This table necessarily reveals relationship and frequency information. Opaque random user and role IDs, least-privilege database access, auditing, backups protection, and database integrity controls are required compensating measures.

### User claims (`IdentityUserClaim<TKey>` / `AspNetUserClaims`)

| Property | Treatment | Reason and implementation requirement |
|---|---|---|
| `Id` | Plain | Primary key. |
| `UserId` | Plain | Foreign key used to load a user's claims. |
| `ClaimType` | Encrypt + hash | Claim types can disclose sensitive classifications and are used by replace/remove operations. |
| `ClaimValue` | Encrypt + hash when equality operations are enabled; otherwise encrypt | Values may contain PII, tenant identifiers, entitlements or medical/financial classifications. Composite type/value candidate lookup requires plaintext verification. |

Claims require custom generated store overrides for add, replace, remove and equality matching. Loading all claims by `UserId` remains efficient because the foreign key stays plaintext.

### Role claims (`IdentityRoleClaim<TKey>` / `AspNetRoleClaims`)

| Property | Treatment | Reason and implementation requirement |
|---|---|---|
| `Id` | Plain | Primary key. |
| `RoleId` | Plain | Foreign key used to load the role's claims. |
| `ClaimType` | Encrypt + hash | Same policy as user claims. |
| `ClaimValue` | Encrypt + hash when equality operations are enabled; otherwise encrypt | Same policy as user claims. |

This needs a protected role store as well as protected role entity configuration.

### External logins (`IdentityUserLogin<TKey>` / `AspNetUserLogins`)

Identity looks up a user using `LoginProvider` and `ProviderKey`; the default schema uses those values as part of its key. The store contract includes lookup and removal by provider and provider key. See [`IUserLoginStore<TUser>`](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.identity.iuserloginstore-1?view=aspnetcore-10.0).

| Property | Treatment | Reason and implementation requirement |
|---|---|---|
| `UserId` | Plain | Foreign key. |
| `LoginProvider` | Redesign: encrypt + hash | Reveals which external service the user employs and participates in lookup/key structure. |
| `ProviderKey` | Redesign: encrypt + hash | Stable external account identifier and therefore linkable personal data. |
| `ProviderDisplayName` | Encrypt | Display metadata and possible PII. |

Recommended schema: introduce an opaque surrogate login ID as the relational primary key, encrypt the original provider fields, and create a unique composite HMAC index for provider plus provider key. Generated store methods must verify both decrypted fields after candidate retrieval. Do not concatenate values without an unambiguous length-prefix or domain-separated encoding.

### User tokens (`IdentityUserToken<TKey>` / `AspNetUserTokens`)

The default token entity contains `UserId`, `LoginProvider`, `Name`, and `Value`; Microsoft describes it as an authentication token record. See [`IdentityUserToken<TKey>`](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.identity.identityusertoken-1?view=aspnetcore-10.0).

| Property | Treatment | Reason and implementation requirement |
|---|---|---|
| `UserId` | Plain | Foreign key and part of the default composite key. |
| `LoginProvider` | Redesign: encrypt + hash | Routing/key component used with `Name`. The small provider vocabulary makes it easy to guess if left exposed. |
| `Name` | Redesign: encrypt + hash | Token-purpose metadata can reveal authenticator, recovery-code or provider-token use. |
| `Value` | Encrypt | Highest-priority secret payload. It can contain authenticator keys, recovery codes or provider tokens. Never hash unless a particular token protocol explicitly requires equality lookup. |

The protected token entity therefore needs a surrogate UUIDv7 relational key generated with `Guid.CreateVersion7()`. Encrypt the original provider/name values, add a composite domain-separated HMAC routing index over `UserId`, provider and name, and encrypt `Value`. The generated store must preserve Identity's logical uniqueness over those three values. UUIDv7 improves ordered inserts but exposes approximate record creation time and order. Token configuration and provider names are documented in [ASP.NET Core Identity configuration](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/identity-configuration?view=aspnetcore-10.0).

The approved schema, canonical binary HMAC input, store behaviour, result boundary, migration constraints and tests are specified in the [protected Identity user-token design](identity-token-security-design.md).

### Passkeys (`IdentityUserPasskey<TKey>` / provider-defined table name)

Identity 10 includes passkey persistence in the `IdentityUserContext` model. The entity exposes `UserId`, `CredentialId`, and an `IdentityPasskeyData` record containing the public key, attestation/client data, timestamps, counters, backup flags, name and transports.

| Property | Treatment | Reason and implementation requirement |
|---|---|---|
| `UserId` | Plain | Foreign key. |
| `CredentialId` | Redesign: encrypt + hash | Lookup identifier. Although not a private key, it is stable and linkable. Use an opaque surrogate relational key plus HMAC candidate lookup. |
| `Data.PublicKey` | Encrypt separately | Public rather than secret, but integrity-critical and associated with an account. |
| `Data.AttestationObject` | Encrypt | Can disclose authenticator/vendor and attestation metadata. |
| `Data.ClientDataJson` | Encrypt | Protocol record that can contain origin and contextual metadata. |
| `Data.Name` | Encrypt separately | User/device label. |
| `Data.Transports` | Encrypt separately | Authenticator capability metadata; requires a stable representation for the string collection. |
| `Data.CreatedAt` | Encrypt separately | Credential lifecycle metadata; requires `DateTimeOffset` protection. |
| `Data.IsBackedUp`, `Data.IsBackupEligible`, `Data.IsUserVerified` | Encrypt separately | Credential state metadata; requires Boolean protection. |
| `Data.SignCount` | Encrypt separately | Replay-detection state; requires unsigned-integer protection and tested atomic/concurrent updates. |

Passkeys use separate protected `byte[]`, `DateTimeOffset`, `bool`, `uint`, `string`, and string-collection fields. Each stored representation is versioned even though the fields remain independently protected. The credential ID has a keyed route for lookup, followed by fixed-time verification of the decrypted candidate. No private passkey material is stored because the server should not possess it.

## Cross-cutting requirements

### Query and collision behaviour

- Every deterministic lookup must use HMAC with an externally provisioned stable search-key handle.
- HMAC input must include entity, property and logical-domain separation.
- Multi-field lookups must use an unambiguous structured encoding.
- Every HMAC result is a candidate set. Decrypt and compare every candidate in constant-time where the compared value is a credential or token.
- A unique HMAC collision must fail closed at insert time. It must never resolve to the wrong account.
- Direct EF predicates over protected source properties should produce analyzer diagnostics.

### Indexes and constraints

- Remove Identity's plaintext indexes only after replacement HMAC indexes are configured.
- Preserve uniqueness for normalized username and normalized role name.
- Email uniqueness must match `IdentityOptions.User.RequireUniqueEmail`. Both modes are supported, and mismatched model/options configuration must fail during startup validation.
- Composite external-login and claim indexes must encode all participating fields in the keyed input.
- Index sizes must be based on HMAC output, not ciphertext or PQC payload size.

### Logging and diagnostics

- Never log plaintext, ciphertext, token values, password hashes, security stamps, search-key handles, or full HMAC values.
- Exceptions may identify entity/property and logical source key, but not protected values.
- Enable EF sensitive-data logging only with disposable synthetic data.
- Audit administrative changes to keys and protected schema separately from application logs.

### Migration and recovery

- Existing installations require explicit migrations, backfill, verification and rollback planning.
- Do not generate a new search key during deployment or application startup.
- Search-key retirement requires recalculating every dependent HMAC column.
- Encryption-key retirement requires decrypting and re-encrypting every datum using the retired handle.
- Large-table migration must define batching, transaction boundaries, availability impact and resumability.
- Backups made before re-encryption remain protected by the old keys and must be included in retirement planning.

## Proposed implementation order

1. **User baseline — implemented:** protected user strings, keyed username/email lookup, collision verification, generated user store, removal of plaintext lookup indexes, support for both email-uniqueness modes, and startup options validation.
2. **Token records — provider integration, benchmarks, and SQLite/PostgreSQL migration tooling complete:** UUIDv7 surrogate-key entity, encrypted provider/name/value fields, generated composite-HMAC routing, generated store integration, adversarial hardening, raw-storage verification, indexed PostgreSQL query-plan verification, concurrent insertion tests and performance baselines are implemented. The offline state/coordinator, both provider executors, and operator console include generated protection plus all-row runtime verification, durable non-secret checkpoints, a protected-write gate, safe pre-write rollback, explicit approved plaintext removal, DDL/checkpoint crash reconciliation, integrity gates, cancellation/corruption failure injection, and one acknowledged transition per command.
3. **Roles — new-schema runtime complete:** opt-in derived role entities can encrypt `Name`, encrypt and uniquely HMAC-index `NormalizedName`, remove `RoleNameIndex`, and use a generated collision-verifying lookup plus generated `RoleStore`. `RoleManager.FindByNameAsync` is verified end to end against SQLite, raw storage contains only ciphertext and keyed hashes, and multiple verified matches fail closed. Existing-row migration and PostgreSQL role-specific integration coverage remain before release completion.
4. **Claims — new-schema runtime complete:** derived user/role claim entities encrypt type and value and carry a domain-separated composite HMAC over owner ID, type, and value. Generated claim-aware stores support add, replace, remove, protected tokens in the same context, collision verification, and fail-closed mismatch handling. `GetUsersForClaimAsync` currently uses a verified scan because the owner-specific route cannot serve a global type/value query. Existing-row migrations, a separately reviewed global route, PostgreSQL claim-specific integration tests, and benchmarks remain before release completion.
5. **External logins — new-schema SQLite runtime complete:** the provider-neutral login entity uses a UUIDv7 surrogate key, encrypts provider, provider key, and display name, and has a unique domain-separated provider/key HMAC route. Generated stores cover add, find, list, and remove operations, verify decrypted collision candidates, and compose with protected claims and tokens. Existing-row migrations, PostgreSQL-specific integration coverage, concurrency tests, and benchmarks remain before release completion.
6. **Passkeys:** add typed per-field protection and settle each field's storage, integrity and concurrency behaviour before implementation.
7. **Typed operational fields:** decide whether metadata leakage warrants converters for Boolean, timestamp and counter fields; performance-test before changing them.
8. **Custom key types:** generalise generated stores beyond the current string-key `IdentityDbContext<TUser>` boundary.

## Acceptance criteria for each phase

- Standard `UserManager`, `RoleManager` and `SignInManager` workflows continue to pass.
- Raw database inspection finds no protected plaintext or password verifier fragments.
- Lookup tests include forced HMAC collisions and multiple verified-match failure.
- Missing or mismatched source-key configuration prevents startup.
- Insert, update, delete, uniqueness and concurrency behaviour is tested on SQLite and PostgreSQL before public release.
- Migrations are reviewed to confirm that old plaintext columns and indexes are actually removed.
- Logs and exception messages are checked for protected values.
- Allocation, query-count, candidate-count and latency benchmarks are recorded.

## Remaining design work

- Define the surrogate relational key and composite HMAC input format for external-login entities. The token format is now defined in the protected user-token design.
- Completed: add supported storage encodings for each passkey field type without collapsing the record into one opaque blob, plus generated passkey add/update, lookup, list, and removal operations.
- Continue operational and failure-injection hardening around both completed provider workflows before making migration tooling packable.

The generator must not silently protect additional Identity entities merely because the Identity package is referenced. Each phase remains an explicit opt-in until its entity model, generated store operations, migrations and tests are complete.
