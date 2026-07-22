namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// Represents the high-level visual state of the Agent workspace page.
/// Derived centrally from existing application state (busy flag, result availability).
/// </summary>
public enum AgentPageState
{
    /// <summary>No scan running and no active results — show idle hero + mission cards.</summary>
    Idle,

    /// <summary>A scan or query is in progress — show live progress workspace.</summary>
    Running,

    /// <summary>A completed audit with findings exists — show results master-detail.</summary>
    Results,

    /// <summary>The last operation failed — show error state.</summary>
    Error
}
