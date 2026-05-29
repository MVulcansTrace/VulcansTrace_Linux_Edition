namespace VulcansTrace.Linux.Agent.Rules;

/// <summary>
/// Shared retention settings for expired suppression entries.
/// </summary>
public static class SuppressionRetentionPolicy
{
    /// <summary>
    /// Number of days to keep expired suppressions available for review before pruning.
    /// </summary>
    public const int ExpiredRetentionDays = 30;
}
