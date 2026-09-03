# Mrbr.Encryption.Data.Identity

Identity integration for `Mrbr.Encryption.Data`, providing collision-safe username and email lookup over source-generated keyed deterministic hashes.

## Current scope

- ASP.NET Core Identity users and roles with `string` keys.
- A reusable `UserStore` base that delegates username and email searches to source-generated, plaintext-verifying lookups.
- An Entity Framework model helper that removes Identity's plaintext lookup indexes before generated HMAC indexes are added.

The consuming application continues to own its user type, `IdentityDbContext`, source-key attributes, and deployment configuration. This keeps decisions about which Identity properties are sensitive and which key domains protect them explicit.

## Lookup contract

Implement `IEncryptedIdentityUserLookup<TUser>` by calling the source-generated `Find...MatchesAsync` methods for `NormalizedUserName` and `NormalizedEmail`. Derive the application's store from `EncryptedIdentityUserStore<TUser, TRole, TContext>` and pass that lookup implementation to its constructor.

The store accepts zero or one verified plaintext match. More than one verified match is treated as an invalid security state and throws rather than selecting an arbitrary account.

## Model configuration

Call `RemoveIdentityPlaintextLookupIndexes<TUser>()` after `base.OnModelCreating(modelBuilder)` and before `AddMrbrGeneratedEncryption(...)`:

```csharp
protected override void OnModelCreating(ModelBuilder modelBuilder)
{
    base.OnModelCreating(modelBuilder);
    modelBuilder.RemoveIdentityPlaintextLookupIndexes<ApplicationUser>();
    modelBuilder.AddMrbrGeneratedEncryption(dataProtectionService, sourceKeyMapConfig);
}
```

The generated unique HMAC indexes then replace Identity's conventional plaintext lookup indexes.

## Security boundary

Database HMAC matches are candidates, not proof of plaintext equality. The lookup implementation must use the generated collision-verifying query methods, which decrypt candidate rows and compare normalized plaintext before returning them.

The initial package deliberately does not yet cover custom Identity key types, external-login tables, token tables, claims, or automated generation of the lookup adapter.
