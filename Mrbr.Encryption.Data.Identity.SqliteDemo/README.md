# SQLite encrypted Identity showcase

This console application demonstrates the provider-neutral `Mrbr.Encryption.Data.Identity` types on SQLite. It uses the same library entities and generated stores that another Entity Framework Core provider can use; only the EF provider and connection string are SQLite-specific.

The showcase exercises:

- encrypted username, normalized username, email, normalized email, phone, and operational user fields;
- keyed lookup hashes for users and roles;
- encrypted user and role claims with collision-verifying routes;
- encrypted authentication tokens with UUIDv7 identifiers;
- encrypted external logins with UUIDv7 identifiers;
- encrypted passkeys and credential routing; and
- normal `UserManager` and `RoleManager` operations over decrypted values.

## Run

```powershell
dotnet run --project .\Mrbr.Encryption.Data.Identity.SqliteDemo
```

Each run creates a uniquely named SQLite database in this project directory and leaves it in place for inspection. To select the output path explicitly:

```powershell
dotnet run --project .\Mrbr.Encryption.Data.Identity.SqliteDemo -- .\showcase.db
```

Use a new path for each run. The application never deletes or overwrites a database. It prints both the plaintext values returned through Identity and the protected values stored in SQLite.

## Security note

The deterministic in-process key material in this project exists only to make the example reproducible. Production applications must provision their key sources and stable search-key handles through protected deployment configuration, keep keys outside source control, and establish rotation, backup, and recovery procedures.

The SQLite database contains encrypted application data but is still a review artifact, not a production security boundary. Database, journal, backup, and exported copies all require appropriate access controls.
