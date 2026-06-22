namespace VulcansTrace.Linux.Agent.Remediation;

/// <summary>
/// Deterministic categories for common remediation step failures.
/// </summary>
public enum FailureCategory
{
    /// <summary>A required tool, package, or file is missing.</summary>
    MissingDependency,

    /// <summary>The command failed due to insufficient privileges.</summary>
    PermissionIssue,

    /// <summary>The change is already present or conflicts with existing configuration.</summary>
    AlreadyConfigured,

    /// <summary>A referenced service is missing or cannot be started.</summary>
    ServiceMissing,

    /// <summary>The command or argument was malformed.</summary>
    MalformedCommand,

    /// <summary>The failure does not match any known pattern.</summary>
    UnknownFailure
}
