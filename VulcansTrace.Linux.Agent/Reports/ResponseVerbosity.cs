namespace VulcansTrace.Linux.Agent.Reports;

/// <summary>
/// Hint for chat renderers about how much of an <see cref="AgentResult"/> to surface.
/// Render-only: it never alters findings, <c>LastResult</c>, audit history, or scorecards.
/// </summary>
public enum ResponseVerbosity
{
    /// <summary>Default full rendering (capability report, narrative, finding groups, warnings).</summary>
    Normal,

    /// <summary>Terse rendering: lead summary plus a one-line findings count; suppresses the capability report, narrative, per-category finding groups, and raw warnings.</summary>
    Terse
}
