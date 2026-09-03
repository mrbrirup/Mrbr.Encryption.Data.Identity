# Mrbr.Encryption.Data.Identity.Migration.PostgreSql

This non-packaged project implements the PostgreSQL 17 executor for the offline protected Identity token migration. It shares the provider-neutral checkpoint/state contracts and generated application adapter with the SQLite executor.

The executor provides:

- strict read-only preflight validation of the legacy table and PostgreSQL catalogs;
- native `uuid` UUIDv7 token identifiers and `varchar(64)` routing hashes;
- deterministic source traversal using ordinal `COLLATE "C"` ordering;
- bounded, idempotent batch transactions;
- durable non-secret checkpoints protected by a transaction-scoped advisory lock;
- transactional cutover and rollback with explicit `ACCESS EXCLUSIVE` table locks;
- all-row generated runtime verification before protected writes can be accepted;
- explicit retained-plaintext removal; and
- reconciliation when PostgreSQL commits DDL immediately before checkpoint persistence fails.

The application remains responsible for maintenance/read-only enforcement, backups, capacity assessment, database permissions, external audit evidence, and stable externally provisioned KeyManager/EncryptionManager configuration. The executor never creates or replaces keys.

Run the integration suite through `./run-postgresql-tests.ps1` at the repository root. It uses the disposable PostgreSQL 17 Docker configuration and removes the database container afterward.
