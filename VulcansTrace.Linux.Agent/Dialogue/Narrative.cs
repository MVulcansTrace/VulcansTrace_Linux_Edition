namespace VulcansTrace.Linux.Agent.Dialogue;

/// <summary>
/// A composed narrative response broken into traceable paragraphs.
/// Each paragraph is backed by one or more source ids (finding rule IDs,
/// posture correlation pattern IDs, or rule memory entry keys).
/// </summary>
public sealed record Narrative
{
    /// <summary>One-line summary of the result.</summary>
    public string Summary { get; init; } = string.Empty;

    /// <summary>Paragraph describing the key findings.</summary>
    public string KeyFindingsParagraph { get; init; } = string.Empty;

    /// <summary>Paragraph describing cross-category correlations, if any.</summary>
    public string CorrelationsParagraph { get; init; } = string.Empty;

    /// <summary>Paragraph describing system-level trajectory, if enough history exists.</summary>
    public string TrajectoryParagraph { get; init; } = string.Empty;

    /// <summary>Paragraph proactively flagging returned findings, if any.</summary>
    public string ProactiveAlertsParagraph { get; init; } = string.Empty;

    /// <summary>Paragraph describing ordered attack chains, if any.</summary>
    public string AttackChainsParagraph { get; init; } = string.Empty;

    /// <summary>Paragraph adding remediation wisdom for recurring findings, if any.</summary>
    public string RemediationWisdomParagraph { get; init; } = string.Empty;

    /// <summary>Paragraph adding memory-backed continuity, if any.</summary>
    public string MemoryParagraph { get; init; } = string.Empty;

    /// <summary>Paragraph surfacing long-horizon coverage blind spots after partial audits.</summary>
    public string CoverageParagraph { get; init; } = string.Empty;

    /// <summary>Paragraph suggesting next steps.</summary>
    public string NextStepsParagraph { get; init; } = string.Empty;

    /// <summary>Full multi-paragraph text.</summary>
    public string FullText => string.Join("\n\n", new[]
    {
        Summary,
        KeyFindingsParagraph,
        CorrelationsParagraph,
        TrajectoryParagraph,
        ProactiveAlertsParagraph,
        AttackChainsParagraph,
        RemediationWisdomParagraph,
        MemoryParagraph,
        CoverageParagraph,
        NextStepsParagraph
    }.Where(p => !string.IsNullOrWhiteSpace(p)));

    /// <summary>Rule IDs, posture pattern IDs, and memory keys cited by this narrative.</summary>
    public IReadOnlyList<string> SourceIds { get; init; } = Array.Empty<string>();
}
