namespace Mrbr.Encryption.Data.Identity.Migration;

/// <summary>Identifies an expected migration-control failure without using an exception for control flow.</summary>
public enum IdentityTokenMigrationFailureCode
{
    /// <summary>No failure occurred.</summary>
    None = 0,
    /// <summary>The requested stage does not immediately follow the durable current stage.</summary>
    InvalidStageTransition = 1,
    /// <summary>A supplied migration identifier is not a non-empty UUIDv7 value.</summary>
    InvalidMigrationIdentifier = 2,
    /// <summary>Row counters are negative, decreasing or inconsistent with the current stage.</summary>
    InvalidRowCounts = 3,
    /// <summary>The source row count changed after the read-only preflight snapshot.</summary>
    SourceChanged = 4,
    /// <summary>Protected target verification did not account for every source row.</summary>
    VerificationFailed = 5,
    /// <summary>A table-swap rollback is unsafe because the protected table has accepted writes.</summary>
    RollbackUnsafe = 6,
    /// <summary>The configured batch size is outside the supported range.</summary>
    InvalidBatchSize = 7,
    /// <summary>A source or target adapter did not account for every row in a requested batch.</summary>
    IncompleteBatch = 8,
    /// <summary>A source row violates the legacy token schema contract.</summary>
    InvalidSourceRow = 9,
    /// <summary>Protected payload input or output is malformed.</summary>
    InvalidPayload = 10,
    /// <summary>Cryptographic authentication failed while verifying a protected row.</summary>
    AuthenticationFailed = 11,
    /// <summary>A required key could not be found.</summary>
    KeyNotFound = 12,
    /// <summary>A required key is temporarily unavailable or inactive.</summary>
    KeyUnavailable = 13,
    /// <summary>A required key has been retired.</summary>
    KeyRetired = 14,
    /// <summary>The configured protection algorithm is unsupported.</summary>
    UnsupportedAlgorithm = 15,
    /// <summary>A routing-HMAC candidate did not match the source plaintext.</summary>
    HashMismatch = 16,
    /// <summary>More than one protected row verified for one source route.</summary>
    AmbiguousMatch = 17,
    /// <summary>A bounded target persistence or uniqueness conflict could not be resolved safely.</summary>
    PersistenceConflict = 18,
    /// <summary>An irreversible operator action did not include every required explicit acknowledgement.</summary>
    OperatorApprovalRequired = 19,
    /// <summary>An implementation reported a failure with no more specific stable code.</summary>
    Unknown = 255
}
