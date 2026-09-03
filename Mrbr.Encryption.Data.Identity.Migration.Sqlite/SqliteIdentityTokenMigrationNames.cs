namespace Mrbr.Encryption.Data.Identity.Migration.Sqlite;

/// <summary>Derives fixed SQLite object names solely from a validated migration identifier.</summary>
public sealed class SqliteIdentityTokenMigrationNames
{
    /// <summary>Initializes names for one UUIDv7 migration.</summary>
    public SqliteIdentityTokenMigrationNames(Guid migrationId)
    {
        if (migrationId == Guid.Empty || migrationId.Version != 7)
        {
            throw new ArgumentException("A non-empty UUIDv7 migration identifier is required.", nameof(migrationId));
        }

        string suffix = migrationId.ToString("N");
        ShadowTable = "AspNetUserTokens_MrbrProtected_" + suffix;
        LegacyTable = "AspNetUserTokens_MrbrLegacy_" + suffix;
        ShadowRouteIndex = "IX_MrbrProtectedTokenRoute_" + suffix;
        ShadowUserIndex = "IX_MrbrProtectedTokenUser_" + suffix;
    }

    /// <summary>Gets the final application table name.</summary>
    public string ApplicationTable => "AspNetUserTokens";

    /// <summary>Gets the protected shadow-table name.</summary>
    public string ShadowTable { get; }

    /// <summary>Gets the retained legacy-table name.</summary>
    public string LegacyTable { get; }

    /// <summary>Gets the temporary unique route-index name.</summary>
    public string ShadowRouteIndex { get; }

    /// <summary>Gets the temporary user-index name.</summary>
    public string ShadowUserIndex { get; }
}
