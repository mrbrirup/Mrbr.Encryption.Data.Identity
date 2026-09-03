using BenchmarkDotNet.Running;

namespace Mrbr.Encryption.Data.Identity.Benchmarks;

internal static class Program
{
    private static void Main(string[] args) =>
        BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args);
}
