using VulcansTrace.Linux.Agent.Explanations;

namespace VulcansTrace.Linux.Agent.Remediation;

/// <summary>
/// Defines which remediation commands are eligible for automatic execution.
/// Separates detection from action by gating execution on explicit safety policy.
/// </summary>
public sealed record AutoFixPolicy
{
    /// <summary>
    /// Creates a default conservative policy: only read-only verification commands.
    /// This is effectively a no-op for fixes, serving as the safest baseline.
    /// </summary>
    public static AutoFixPolicy Conservative() => new();

    /// <summary>
    /// Creates a standard policy that allows config changes with rollback guidance.
    /// Does NOT allow service restarts, package installs, destructive, or unknown commands.
    /// </summary>
    public static AutoFixPolicy Standard() => new()
    {
        AllowConfigChange = true
    };

    /// <summary>
    /// Creates an aggressive policy that allows config changes and service restarts.
    /// Still blocks destructive, unknown, and package operations.
    /// </summary>
    public static AutoFixPolicy Aggressive() => new()
    {
        AllowConfigChange = true,
        AllowServiceRestart = true
    };

    /// <summary>Whether read-only (verification) commands are allowed.</summary>
    public bool AllowReadOnly { get; init; } = true;

    /// <summary>Whether configuration-changing commands are allowed.</summary>
    public bool AllowConfigChange { get; init; }

    /// <summary>Whether service restart/start/stop commands are allowed.</summary>
    public bool AllowServiceRestart { get; init; }

    /// <summary>Whether package install/remove commands are allowed.</summary>
    public bool AllowPackageInstall { get; init; }

    /// <summary>Whether destructive commands (flush, rm -rf, mkfs, etc.) are allowed.</summary>
    public bool AllowDestructive { get; init; }

    /// <summary>Whether unclassified commands are allowed.</summary>
    public bool AllowUnknown { get; init; }

    /// <summary>
    /// Whether to require the remediation plan to pass <see cref="Reports.RemediationPlanValidator.Validate"/>
    /// before any commands from that section are executed.
    /// </summary>
    public bool RequireValidation { get; init; } = true;

    /// <summary>
    /// Whether to require explicit rollback guidance for every section that will be executed.
    /// </summary>
    public bool RequireRollbackGuidance { get; init; } = true;

    /// <summary>
    /// Determines whether a command with the given safety classification is permitted.
    /// </summary>
    public bool IsPermitted(CommandSafety safety) => safety switch
    {
        CommandSafety.ReadOnly => AllowReadOnly,
        CommandSafety.ConfigChange => AllowConfigChange,
        CommandSafety.ServiceRestart => AllowServiceRestart,
        CommandSafety.PackageInstall => AllowPackageInstall,
        CommandSafety.Destructive => AllowDestructive,
        CommandSafety.Unknown => AllowUnknown,
        _ => false
    };

    /// <summary>
    /// Returns a human-readable description of what this policy permits.
    /// </summary>
    public string Describe()
    {
        var parts = new List<string>();
        if (AllowReadOnly) parts.Add("read-only verification");
        if (AllowConfigChange) parts.Add("config changes");
        if (AllowServiceRestart) parts.Add("service restarts");
        if (AllowPackageInstall) parts.Add("package installs");
        if (AllowDestructive) parts.Add("destructive commands");
        if (AllowUnknown) parts.Add("unclassified commands");

        if (parts.Count == 0)
            return "blocks all commands";

        return "allows: " + string.Join(", ", parts);
    }
}
