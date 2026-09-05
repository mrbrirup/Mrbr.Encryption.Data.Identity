using BenchmarkDotNet.Running;

namespace Mrbr.Encryption.Data.Identity.Benchmarks;

internal static class Program
{
    private static void Main(string[] args)
    {
        if (args.Length >= 1 && args[0] == "--smoke")
        {
            int count = args.Length == 2 ? int.Parse(args[1], System.Globalization.CultureInfo.InvariantCulture) : 1;
            foreach (IdentityProtectionProfile profile in Enum.GetValues<IdentityProtectionProfile>())
            {
                using IdentityBenchmarkHost host = IdentityBenchmarkHost.Create(profile);
                host.CreateUsersAsync(count).GetAwaiter().GetResult();
                host.LookupUsersAsync(count).GetAwaiter().GetResult();
                Console.WriteLine($"{profile}: create and lookup passed");
            }
            return;
        }

        BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args);
    }
}
