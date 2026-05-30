namespace VulcansTrace.Linux.Agent.Scanners;

/// <summary>
/// Indicates the availability status of a data source used by a scanner.
/// </summary>
public enum CapabilityStatus
{
    /// <summary>The data source was available and returned usable data.</summary>
    Available,

    /// <summary>The data source could not be found or returned an error.</summary>
    Unavailable,

    /// <summary>The data source is present but access was restricted by permissions.</summary>
    PermissionLimited,

    /// <summary>The status of the data source is unknown.</summary>
    Unknown
}

/// <summary>
/// Records the availability of a single system data source (e.g. iptables, ss, systemctl).
/// </summary>
public sealed record DataSourceCapability
{
    /// <summary>Human-readable name of the data source.</summary>
    public string SourceName { get; init; } = string.Empty;

    /// <summary>Availability status.</summary>
    public CapabilityStatus Status { get; init; }

    /// <summary>Optional detail message (e.g. stderr output).</summary>
    public string? Detail { get; init; }

    /// <summary>
    /// Classifies a command-backed data source from its process result.
    /// </summary>
    public static CapabilityStatus FromCommandResult(bool success, string? stdout, string? stderr)
    {
        if (ContainsPermissionDenied(stdout) || ContainsPermissionDenied(stderr))
            return CapabilityStatus.PermissionLimited;

        return success ? CapabilityStatus.Available : CapabilityStatus.Unavailable;
    }

    /// <summary>
    /// Determines whether command output indicates permission-limited visibility.
    /// </summary>
    public static bool ContainsPermissionDenied(string? value) =>
        value?.Contains("Permission denied", StringComparison.OrdinalIgnoreCase) == true;
}
