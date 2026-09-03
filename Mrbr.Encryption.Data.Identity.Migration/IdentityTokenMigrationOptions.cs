namespace Mrbr.Encryption.Data.Identity.Migration;

/// <summary>Controls bounded provider-neutral token migration batches.</summary>
public sealed class IdentityTokenMigrationOptions
{
    /// <summary>Gets the default number of rows in one transaction boundary.</summary>
    public const int DefaultBatchSize = 500;

    /// <summary>Gets the largest supported batch size.</summary>
    public const int MaximumBatchSize = 10_000;

    /// <summary>Gets or initializes the number of rows requested per committed batch.</summary>
    public int BatchSize { get; init; } = DefaultBatchSize;

    internal bool IsValid => BatchSize is > 0 and <= MaximumBatchSize;
}
