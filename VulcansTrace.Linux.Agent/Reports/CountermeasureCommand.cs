using VulcansTrace.Linux.Agent.Explanations;

namespace VulcansTrace.Linux.Agent.Reports;

/// <summary>
/// A single active countermeasure command with its rollback counterpart and safety metadata.
/// </summary>
public sealed record CountermeasureCommand
{
    /// <summary>The apply command text.</summary>
    public required string Command { get; init; }

    /// <summary>The exact rollback / undo command text.</summary>
    public required string RollbackCommand { get; init; }

    /// <summary>Safety classification of the apply command.</summary>
    public CommandSafety Safety { get; init; } = CommandSafety.Unknown;

    /// <summary>Detailed structural analysis of the apply command.</summary>
    public CommandAnalysis Analysis { get; init; } = new();

    /// <summary>The kind of countermeasure.</summary>
    public CountermeasureType Type { get; init; }

    /// <summary>The IP or host the countermeasure targets.</summary>
    public string TargetHost { get; init; } = string.Empty;
}
