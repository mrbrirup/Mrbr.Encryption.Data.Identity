namespace Mrbr.Encryption.Data.Identity.Migration.PostgreSql;

/// <summary>Derives PostgreSQL identifiers within the 63-byte default identifier limit.</summary>
public sealed class PostgreSqlIdentityTokenMigrationNames
{
    /// <summary>Initializes names for one UUIDv7 migration.</summary>
    public PostgreSqlIdentityTokenMigrationNames(Guid migrationId)
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

    public string ApplicationTable => "AspNetUserTokens";
    public string ShadowTable { get; }
    public string LegacyTable { get; }
    public string ShadowRouteIndex { get; }
    public string ShadowUserIndex { get; }
    public string FinalRouteIndex => "IX_AspNetUserTokens_RoutingHash";
    public string FinalUserIndex => "IX_AspNetUserTokens_UserId";
}
