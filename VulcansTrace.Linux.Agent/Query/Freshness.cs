namespace VulcansTrace.Linux.Agent.Query;

/// <summary>
/// The user's expressed preference about whether an audit question should reuse the most recent
/// completed audit or run a fresh scan. Orthogonal to the primary <see cref="AgentIntent"/>.
/// </summary>
public enum Freshness
{
    /// <summary>No explicit preference; the caller's default policy applies (currently: scan).</summary>
    Auto,

    /// <summary>Explicit request to (re)run a fresh scan (e.g. "re-scan", "check again", "fresh audit").</summary>
    ForceRefresh,

    /// <summary>Explicit request to answer from the existing audit without scanning (e.g. "what did you find", "from your audit").</summary>
    ReuseOnly
}
