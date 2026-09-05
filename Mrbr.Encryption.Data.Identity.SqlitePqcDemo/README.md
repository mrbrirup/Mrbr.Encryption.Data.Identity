# SQLite post-quantum Identity showcase

This runnable showcase uses the provider-neutral encrypted ASP.NET Core Identity entities and stores with SQLite. Protected values use the hybrid `MlKem768` profile: FIPS 203 ML-KEM-768 establishes a per-value secret and AES-256-GCM provides authenticated data encryption. Deterministic lookups remain separately protected with keyed HMAC-SHA-256 hashes.

Run it from this directory:

```powershell
dotnet run
```

The application prints the retained database path, completes Identity user, role, claim, external-login, token, and passkey workflows, and then prints representative raw database rows. You can also provide a new database path as the sole argument. Existing databases are never overwritten or deleted.

The embedded key material is deliberately deterministic for an inspectable demonstration. Never use these demonstration keys in production; provision key sources and search-key handles from your real secret-management boundary.
