using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Columns;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Order;
using Mrbr.Encryption.Data.Common.Results;
using Mrbr.Encryption.Data.EntityFramework.Services;

namespace Mrbr.Encryption.Data.Identity.Benchmarks;

[MemoryDiagnoser]
[CategoriesColumn]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
[Orderer(SummaryOrderPolicy.FastestToSlowest)]
public class IdentityTokenPrimitiveBenchmarks
{
    private const string RouteDomain = "Mrbr.Encryption.Data.Identity/UserTokenRoute";
    private readonly string[] _route = ["4e31db44-f82c-42bf-bdcb-94445091e5f5", "ExampleProvider", "RefreshToken"];
    private BenchmarkProtectionFixture _fixture = null!;
    private string _encryptedValue = null!;

    [GlobalSetup]
    public void Setup()
    {
        _fixture = new BenchmarkProtectionFixture();
        _encryptedValue = _fixture.Service.Encrypt("benchmark-token-secret", _fixture.ValueEncryptionConfiguration);
    }

    [GlobalCleanup]
    public void Cleanup() => _fixture.Dispose();

    [Benchmark(Baseline = true)]
    [BenchmarkCategory("Identifier")]
    public Guid CreateVersion4Guid() => Guid.NewGuid();

    [Benchmark]
    [BenchmarkCategory("Identifier")]
    public Guid CreateVersion7Guid() => Guid.CreateVersion7();

    [Benchmark]
    [BenchmarkCategory("Protection")]
    public byte[] EncodeCompositeRoute() => CompositeHashInputEncoder.Encode(RouteDomain, _route);

    [Benchmark]
    [BenchmarkCategory("Protection")]
    public ProtectionResult<string> ComputeCompositeRouteHmac() =>
        _fixture.Service.ComputeCompositeSearchHash(RouteDomain, _route, _fixture.RouteHashConfiguration);

    [Benchmark]
    [BenchmarkCategory("Protection")]
    public string EncryptTokenValue() =>
        _fixture.Service.Encrypt("benchmark-token-secret", _fixture.ValueEncryptionConfiguration);

    [Benchmark]
    [BenchmarkCategory("Protection")]
    public string DecryptTokenValue() =>
        _fixture.Service.Decrypt(_encryptedValue, _fixture.ValueEncryptionConfiguration);

}

[MemoryDiagnoser]
public class IdentityTokenCandidateBenchmarks
{
    private const string Provider = "ExampleProvider";
    private const string Name = "RefreshToken";
    private Candidate[] _candidates = null!;

    [Params(1, 8, 32)]
    public int CandidateCount { get; set; }

    [GlobalSetup]
    public void Setup() =>
        _candidates = Enumerable.Range(0, CandidateCount)
            .Select(index => index == CandidateCount - 1
                ? new Candidate(Provider, Name)
                : new Candidate("collision-" + index, "other-" + index))
            .ToArray();

    [Benchmark]
    public int VerifyCollisionCandidates()
    {
        int verified = 0;
        foreach (Candidate candidate in _candidates)
        {
            if (string.Equals(candidate.LoginProvider, Provider, StringComparison.Ordinal) &&
                string.Equals(candidate.Name, Name, StringComparison.Ordinal))
            {
                verified++;
            }
        }

        return verified;
    }

    private sealed record Candidate(string LoginProvider, string Name);
}
