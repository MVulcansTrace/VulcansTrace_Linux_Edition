using System;

namespace VulcansTrace.Linux.Avalonia.Services;

/// <summary>
/// Explicit fault gates for isolated desktop scenarios.
/// </summary>
/// <remarks>
/// Fault injection requires machine mode, a scenario identity, and the exact
/// fault value. Normal launches cannot enable a fault accidentally through one
/// stale environment variable. The injected exception still travels through
/// the production Agent operation runner and page-state mapping.
/// </remarks>
public static class ScenarioMode
{
    /// <summary>
    /// Gets whether the next natural-language Agent query should fail at the
    /// Agent dependency boundary.
    /// </summary>
    public static bool ShouldFailAgentQuery =>
        MachineMode.IsEnabled &&
        !string.IsNullOrWhiteSpace(
            Environment.GetEnvironmentVariable("VT_SCENARIO_ID")) &&
        string.Equals(
            Environment.GetEnvironmentVariable("VT_SCENARIO_AGENT_FAILURE"),
            "query",
            StringComparison.OrdinalIgnoreCase);
}
