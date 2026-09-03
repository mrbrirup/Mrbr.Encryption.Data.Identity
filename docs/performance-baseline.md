# Identity token protection performance baseline

Status: benchmark harness and first representative baseline complete  
Target runtime: .NET 11

The harness currently uses BenchmarkDotNet `0.16.0-preview.1`. Stable `0.15.8` compiles for this project but does not recognize the .NET 11 runtime moniker during benchmark validation. This dependency should return to a stable release once a stable version supports .NET 11.

## Purpose

These benchmarks expose the cost of the security boundary instead of presenting one opaque Identity operation. They are intended to detect regressions and guide profiling. They are not service-level guarantees: processor, operating system, runtime build, database latency, durability settings, and key configuration all affect results.

## Benchmark groups

| Group | Comparison | What it isolates |
|---|---|---|
| Identifier | UUIDv4 versus UUIDv7 | Application-side identifier generation. |
| Protection primitives | Composite encoding, keyed HMAC, AES encrypt, AES decrypt | CPU time and managed allocations of individual protection operations. |
| Candidate verification | 1, 8, and 32 candidates | Linear plaintext verification cost after a forced or hypothetical hash collision. |
| Persistence | Plain versus protected insert/lookup/delete | EF/database cycle with identical UUIDv7 and keyed routing-HMAC work; the delta chiefly captures value conversion encryption/decryption and larger stored values. |

The persistence baseline deliberately computes the same routing HMAC in both paths. This prevents the plaintext comparison from hiding routing work and makes the protected/plain ratio easier to interpret.

## Running locally

From the repository root:

```powershell
./run-benchmarks.ps1
./run-benchmarks.ps1 -WithPostgreSql
```

The first command uses an in-memory SQLite database. The second starts the repository's disposable PostgreSQL 17 container and includes both providers. Results are written beneath `BenchmarkDotNet.Artifacts`, which is excluded from source control.

For an existing PostgreSQL instance, set `MRBR_TEST_POSTGRES_CONNECTION_STRING` to an account that may create and drop temporary databases, then run the benchmark project directly.

## Interpretation rules

- Compare results produced on the same machine, power profile, runtime, and database configuration.
- Treat allocation changes and ratios as regression signals before comparing absolute nanoseconds across machines.
- Keep candidate-count measurements separate from ordinary lookups. HMAC collisions should be exceptional, while low-entropy input equality is expected and does not itself create multiple candidates when the composite route is unique.
- Re-run the suite after cryptographic algorithm, payload format, EF provider, schema, or key-service changes.
- Do not weaken authentication, collision verification, or ciphertext integrity to improve a benchmark.

## Recorded baseline

Recorded 2026-09-03 with BenchmarkDotNet's `ShortRun` job (one launch, three warmups, three measured iterations):

- Windows 10 22H2, build 19045.6466;
- Intel Core i7-10750H, 6 physical/12 logical cores;
- .NET SDK `11.0.100-preview.7.26381.103` and .NET runtime `11.0.0-preview.7`;
- PostgreSQL 17 in the repository's loopback Docker container;
- SQLite in-memory with one connection held open for the benchmark lifetime.

### Protection primitives

| Operation | Mean | Managed allocation |
|---|---:|---:|
| UUIDv4 | 86.92 ns | 0 B |
| UUIDv7 | 99.40 ns | 0 B |
| Encode composite route | 218.49 ns | 416 B |
| Decrypt token value | 1.327 us | 976 B |
| Encrypt token value | 1.590 us | 1,128 B |
| Compute composite route HMAC | 2.386 us | 672 B |

UUIDv7 was 1.15 times the UUIDv4 time in this run. This is tens of nanoseconds and is not material beside database persistence.

### Candidate verification

| Candidate count | Mean | Managed allocation |
|---:|---:|---:|
| 1 | 2.145 ns | 0 B |
| 8 | 8.530 ns | 0 B |
| 32 | 30.867 ns | 0 B |

This benchmark compares already-decrypted provider and name strings. A real forced-collision path also pays to decrypt each candidate, so the primitive decryption result must be considered when estimating that exceptional path.

### Persistence cycle

Each operation performs one insert, one indexed lookup, and one delete. Both the plaintext and protected paths compute the same UUIDv7 identifier and keyed composite routing HMAC.

| Provider | Path | Mean | Ratio | Managed allocation | Allocation ratio |
|---|---|---:|---:|---:|---:|
| SQLite | Plain | 144.0 us | 1.00 | 29.48 KB | 1.00 |
| SQLite | Protected | 174.2 us | 1.21 | 35.63 KB | 1.21 |
| PostgreSQL | Plain | 1.798 ms | 1.00 | 33.46 KB | 1.00 |
| PostgreSQL | Protected | 1.820 ms | 1.02 | 39.82 KB | 1.19 |

The PostgreSQL result uses a local container and shows network/database work dominating the added cryptographic CPU time. It must not be generalized to remote production latency or throughput. The short job has only three measured iterations and correspondingly wide confidence intervals; run the default job on release hardware before publishing formal performance claims.
