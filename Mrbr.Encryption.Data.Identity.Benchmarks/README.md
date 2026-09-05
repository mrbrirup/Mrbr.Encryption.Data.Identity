# Identity protection benchmarks

`IdentityUserLoadBenchmarks` compares three otherwise equivalent ASP.NET Core Identity workloads on SQLite:

- `Plain`: Microsoft's standard `IdentityUser`, `IdentityRole`, and EF stores, with no Mrbr protection services.
- `Aes256`: the reusable encrypted Identity model with AES-256-GCM and keyed lookup hashes.
- `MlKem768`: the same encrypted Identity model with hybrid ML-KEM-768 plus AES-256-GCM and the same keyed lookup hashes.

Both user creation and indexed username/email lookup are measured at 1, 100, 1,000, and 10,000 users. Each measured invocation gets a newly created in-memory SQLite database. Provider construction, schema creation, and lookup-data seeding are performed by BenchmarkDotNet iteration setup and are excluded from the timed workload.

Run the publication benchmark in Release mode from this directory:

```powershell
dotnet run -c Release -- --filter "*IdentityUserLoadBenchmarks*" --exporters markdown csv json
```

The 10,000-user ML-KEM runs intentionally perform substantial work and may take considerably longer than the plain and AES cases. Avoid other heavy workloads while collecting publishable results, and record the machine, operating system, .NET runtime, CPU power mode, and commit alongside the exported artifacts.

Run the fast correctness check after changing the harness:

```powershell
dotnet run -- --smoke
```

The deterministic embedded keys are benchmark fixtures only and must not be used in production.
