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
    private static int _agentQueryFailureConsumed;

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

    /// <summary>
    /// Returns <c>true</c> exactly once per process when the Agent-query fault
    /// is armed: the fault fails the NEXT natural-language query, as
    /// documented, so retry scenarios can prove recovery. Subsequent queries
    /// run normally.
    /// </summary>
    public static bool ConsumeAgentQueryFailure() =>
        ShouldFailAgentQuery &&
        System.Threading.Interlocked.Exchange(ref _agentQueryFailureConsumed, 1) == 0;

    /// <summary>Resets the one-shot Agent-query fault latch (test isolation).</summary>
    public static void ResetAgentQueryFailureForTests() =>
        System.Threading.Interlocked.Exchange(ref _agentQueryFailureConsumed, 0);
}
