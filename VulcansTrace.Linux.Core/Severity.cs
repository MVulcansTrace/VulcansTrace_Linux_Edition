namespace VulcansTrace.Linux.Core;

/// <summary>
/// Defines the severity level of a security finding.
/// </summary>
public enum Severity
{
    /// <summary>Informational message, no immediate action required.</summary>
    Info = 0,

    /// <summary>Low severity, monitor for patterns.</summary>
    Low = 1,

    /// <summary>Medium severity, investigate when resources permit.</summary>
    Medium = 2,

    /// <summary>High severity, investigate promptly.</summary>
    High = 3,

    /// <summary>Critical severity, immediate investigation required.</summary>
    Critical = 4
}
