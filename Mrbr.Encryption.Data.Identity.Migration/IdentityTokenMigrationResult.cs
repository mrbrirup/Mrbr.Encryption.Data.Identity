namespace Mrbr.Encryption.Data.Identity.Migration;

/// <summary>Represents either a migration-control value or a known failure.</summary>
/// <typeparam name="T">The successful value type.</typeparam>
public readonly struct IdentityTokenMigrationResult<T>
{
    private readonly T _value;
    private readonly IdentityTokenMigrationFailureCode _failureCode;

    private IdentityTokenMigrationResult(T value)
    {
        _value = value;
        IsSuccess = true;
        _failureCode = IdentityTokenMigrationFailureCode.None;
    }

    private IdentityTokenMigrationResult(IdentityTokenMigrationFailureCode failureCode)
    {
        if (failureCode == IdentityTokenMigrationFailureCode.None)
        {
            throw new ArgumentOutOfRangeException(nameof(failureCode));
        }

        _value = default!;
        IsSuccess = false;
        _failureCode = failureCode;
    }

    /// <summary>Gets whether the operation succeeded.</summary>
    public bool IsSuccess { get; }

    /// <summary>Gets the stable failure code.</summary>
    public IdentityTokenMigrationFailureCode FailureCode => IsSuccess
        ? IdentityTokenMigrationFailureCode.None
        : _failureCode == IdentityTokenMigrationFailureCode.None
            ? IdentityTokenMigrationFailureCode.Unknown
            : _failureCode;

    /// <summary>Gets the successful value.</summary>
    public T Value => IsSuccess
        ? _value
        : throw new InvalidOperationException($"A failed migration result has no value. Failure code: {FailureCode}.");

    /// <summary>Creates a successful result.</summary>
    public static IdentityTokenMigrationResult<T> Success(T value) => new(value);

    /// <summary>Creates a failed result.</summary>
    public static IdentityTokenMigrationResult<T> Failure(IdentityTokenMigrationFailureCode failureCode) => new(failureCode);

    /// <summary>Attempts to retrieve the successful value without throwing.</summary>
    public bool TryGetValue(out T value)
    {
        value = _value;
        return IsSuccess;
    }
}
