using Mrbr.Encryption.Data.Common.Results;

namespace Mrbr.Encryption.Data.Identity;

/// <summary>Reports a known protected-data failure at an ASP.NET Core Identity interface boundary.</summary>
public sealed class IdentityDataProtectionException : Exception
{
    /// <summary>Initializes the exception without including protected values.</summary>
    public IdentityDataProtectionException(ProtectionFailureCode failureCode, string operation)
        : base($"Identity protected-data operation '{operation}' failed with '{failureCode}'.")
    {
        if (failureCode == ProtectionFailureCode.None)
        {
            throw new ArgumentOutOfRangeException(nameof(failureCode));
        }

        FailureCode = failureCode;
    }

    /// <summary>Gets the stable failure code.</summary>
    public ProtectionFailureCode FailureCode { get; }
}
