namespace VulcansTrace.Linux.Agent.Explanations;

/// <summary>
/// Describes the potential impact of a command extracted from agent output.
/// </summary>
public enum CommandSafety
{
    /// <summary>Command is read-only and safe to run for verification.</summary>
    ReadOnly,

    /// <summary>Command modifies system configuration (e.g., iptables, sysctl).</summary>
    ConfigChange,

    /// <summary>Command installs or removes packages.</summary>
    PackageInstall,

    /// <summary>Command starts, stops, restarts, or enables a service.</summary>
    ServiceRestart,

    /// <summary>Command is destructive or irreversible (e.g., rm -rf, flush rules).</summary>
    Destructive,

    /// <summary>Safety could not be determined from the command text.</summary>
    Unknown
}
