namespace VulcansTrace.Linux.Agent.Explanations;

/// <summary>
/// Represents a copyable verification command extracted from an explanation.
/// </summary>
public sealed record CopyableCommand
{
    /// <summary>The display text shown in the UI.</summary>
    public required string DisplayText { get; init; }

    /// <summary>The full command text to copy to the clipboard.</summary>
    public required string FullCommand { get; init; }

    /// <summary>Safety classification of this command.</summary>
    public CommandSafety Safety { get; init; } = CommandSafety.Unknown;

    /// <summary>Detailed structural analysis of this command.</summary>
    public CommandAnalysis Analysis { get; init; } = new();
}
