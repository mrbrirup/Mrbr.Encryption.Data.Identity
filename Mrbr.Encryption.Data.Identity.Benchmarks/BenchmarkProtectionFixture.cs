using Microsoft.Extensions.Options;
using Mrbr.Encryption.Data.Common.Algorithms;
using Mrbr.Encryption.Data.Common.Models;
using Mrbr.Encryption.Data.EntityFramework.Services;
using Mrbr.Service.EncryptionManager.Services;
using Mrbr.Service.KeyManager.Configuration;
using Mrbr.Service.KeyManager.Services;
using System.Security.Cryptography;

namespace Mrbr.Encryption.Data.Identity.Benchmarks;

internal sealed class BenchmarkProtectionFixture : IDisposable
{
    private readonly KeyService _keyService;

    public BenchmarkProtectionFixture()
    {
        var options = new KeyServiceOptions(Options.Create(new KeyServiceConfig
        {
            new KeyServiceEntry(
                keySourceId: 7,
                value: string.Concat(Enumerable.Repeat("Benchmark-only source key material. ", 16)))
        }));
        _keyService = new KeyService(options);
        Service = new EncryptionManagerEntityDataProtectionService(new CryptographicService(_keyService));
        byte[] searchKey = _keyService.GenerateKey256(7, out ulong searchKeyHandle);
        CryptographicOperations.ZeroMemory(searchKey);
        RouteHashConfiguration = new HashedPropertyConfiguration(
            "IdentityTokenLookup",
            7,
            "IdentityTokenLookup",
            searchKeyHandle,
            "Benchmark.ProtectedToken",
            "UserId+LoginProvider+Name",
            "RoutingHash",
            DataHashAlgorithm.HmacSha256,
            DataNormalization.None);
        TokenEncryptionConfiguration = new EncryptedPropertyConfiguration(
            "IdentityToken",
            7,
            "Benchmark.ProtectedToken",
            "LoginProvider",
            DataEncryptionAlgorithm.Aes256);
        NameEncryptionConfiguration = new EncryptedPropertyConfiguration(
            "IdentityToken",
            7,
            "Benchmark.ProtectedToken",
            "Name",
            DataEncryptionAlgorithm.Aes256);
        ValueEncryptionConfiguration = new EncryptedPropertyConfiguration(
            "IdentityCredential",
            7,
            "Benchmark.ProtectedToken",
            "Value",
            DataEncryptionAlgorithm.Aes256);
    }

    public IEntityDataProtectionService Service { get; }

    public HashedPropertyConfiguration RouteHashConfiguration { get; }

    public EncryptedPropertyConfiguration TokenEncryptionConfiguration { get; }

    public EncryptedPropertyConfiguration NameEncryptionConfiguration { get; }

    public EncryptedPropertyConfiguration ValueEncryptionConfiguration { get; }

    public void Dispose() => _keyService.Dispose();
}
