using Microsoft.Data.Sqlite;

namespace Mrbr.Encryption.Data.Identity.Tests;

public sealed class SqliteIdentityTokenMigrationCheckpointStoreTests {
    //[Fact]
    //public async Task SaveAndLoad_RoundTripsValidatedNonSecretCheckpointAcrossInstances()
    //{
    //    string databasePath = Path.Combine(Path.GetTempPath(), $"mrbr-checkpoint-{Guid.NewGuid():N}.db");
    //    string connectionString = $"Data Source={databasePath};Pooling=False";
    //    try
    //    {
    //        IdentityTokenMigrationCheckpoint created = AssertSuccess(
    //            IdentityTokenMigrationStateMachine.Create(expectedSourceRows: 12));
    //        IdentityTokenMigrationCheckpoint preflight = AssertSuccess(
    //            IdentityTokenMigrationStateMachine.Advance(
    //                created,
    //                IdentityTokenMigrationStage.PreflightPassed,
    //                0,
    //                0,
    //                0));

    //        SqliteIdentityTokenMigrationCheckpointStore writer = new(connectionString);
    //        await writer.SaveAsync(created, CancellationToken.None);
    //        await writer.SaveAsync(preflight, CancellationToken.None);

    //        SqliteIdentityTokenMigrationCheckpointStore reader = new(connectionString);
    //        IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint?> loaded = await reader.LoadAsync(
    //            created.MigrationId,
    //            CancellationToken.None);

    //        Assert.True(loaded.IsSuccess);
    //        IdentityTokenMigrationCheckpoint checkpoint = Assert.IsType<IdentityTokenMigrationCheckpoint>(loaded.Value);
    //        Assert.Equal(created.MigrationId, checkpoint.MigrationId);
    //        Assert.Equal(IdentityTokenMigrationStage.PreflightPassed, checkpoint.Stage);
    //        Assert.Equal(12, checkpoint.ExpectedSourceRows);
    //        Assert.Equal(0, checkpoint.SourceRowsScanned);
    //        Assert.False(checkpoint.ProtectedWritesAccepted);
    //        Assert.DoesNotContain("Cursor", await ReadCheckpointColumnsAsync(connectionString), StringComparison.OrdinalIgnoreCase);
    //    }
    //    finally
    //    {
    //        SqliteConnection.ClearAllPools();
    //        File.Delete(databasePath);
    //    }
    //}

    //[Fact]
    //public async Task Save_RejectsAStaleCheckpointInsteadOfOverwritingProgress()
    //{
    //    string databasePath = Path.Combine(Path.GetTempPath(), $"mrbr-checkpoint-{Guid.NewGuid():N}.db");
    //    string connectionString = $"Data Source={databasePath};Pooling=False";
    //    try
    //    {
    //        IdentityTokenMigrationCheckpoint created = AssertSuccess(
    //            IdentityTokenMigrationStateMachine.Create(expectedSourceRows: 1));
    //        IdentityTokenMigrationCheckpoint preflight = AssertSuccess(
    //            IdentityTokenMigrationStateMachine.Advance(
    //                created,
    //                IdentityTokenMigrationStage.PreflightPassed,
    //                0,
    //                0,
    //                0));
    //        SqliteIdentityTokenMigrationCheckpointStore store = new(connectionString);
    //        await store.SaveAsync(preflight, CancellationToken.None);

    //        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
    //            await store.SaveAsync(created, CancellationToken.None));

    //        IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint?> loaded = await store.LoadAsync(
    //            created.MigrationId,
    //            CancellationToken.None);
    //        Assert.Equal(IdentityTokenMigrationStage.PreflightPassed, loaded.Value!.Stage);
    //    }
    //    finally
    //    {
    //        SqliteConnection.ClearAllPools();
    //        File.Delete(databasePath);
    //    }
    //}

    //[Fact]
    //public async Task Load_ReturnsKnownValidationFailureForInvalidMigrationIdentifier()
    //{
    //    SqliteIdentityTokenMigrationCheckpointStore store = new("Data Source=:memory:");

    //    IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint?> result = await store.LoadAsync(
    //        Guid.Empty,
    //        CancellationToken.None);

    //    Assert.False(result.IsSuccess);
    //    Assert.Equal(IdentityTokenMigrationFailureCode.InvalidMigrationIdentifier, result.FailureCode);
    //}

    //private static IdentityTokenMigrationCheckpoint AssertSuccess(
    //    IdentityTokenMigrationResult<IdentityTokenMigrationCheckpoint> result)
    //{
    //    Assert.True(result.IsSuccess, $"Expected success, received {result.FailureCode}.");
    //    return result.Value;
    //}

    private static async Task<string> ReadCheckpointColumnsAsync(string connectionString) {
        await using SqliteConnection connection = new(connectionString);
        await connection.OpenAsync();
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "PRAGMA table_info(\"__MrbrIdentityTokenMigrationCheckpoints\");";
        await using SqliteDataReader reader = await command.ExecuteReaderAsync();
        List<string> columns = [];
        while (await reader.ReadAsync()) {
            columns.Add(reader.GetString(1));
        }

        return string.Join(",", columns);
    }
}
