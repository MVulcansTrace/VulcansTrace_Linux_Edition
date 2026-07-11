namespace VulcansTrace.Linux.Agent.Query;

/// <summary>
/// Parser-side verbosity hint carried on <see cref="AgentQuery.Slots"/>. <c>SecurityAgent</c> maps
/// <see cref="Terse"/> to the render-side <c>Reports.ResponseVerbosity.Terse</c>. Kept separate from
/// the render enum so the Query layer does not depend on the Reports layer.
/// </summary>
public enum QueryVerbosity
{
    /// <summary>Default full rendering.</summary>
    Normal,

    /// <summary>User asked for the short version (e.g. "short version", "be brief", "verdict").</summary>
    Terse
}
