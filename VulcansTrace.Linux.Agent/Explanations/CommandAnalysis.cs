namespace VulcansTrace.Linux.Agent.Explanations;

/// <summary>
/// Detailed analysis result for a shell command, including safety classification
/// and structural metadata such as chains, pipes, redirects, and sudo usage.
/// </summary>
public sealed record CommandAnalysis
{
    /// <summary>Safety classification of the command.</summary>
    public CommandSafety Safety { get; init; } = CommandSafety.Unknown;

    /// <summary>True if the command explicitly uses sudo.</summary>
    public bool RequiresSudo { get; init; }

    /// <summary>True if the command contains chain operators (&&, ||, ;).</summary>
    public bool HasChain { get; init; }

    /// <summary>True if the command contains a pipe (|).</summary>
    public bool HasPipe { get; init; }

    /// <summary>True if the command contains redirects (> >> < 2> 2>&1, etc.).</summary>
    public bool HasRedirect { get; init; }

    /// <summary>True if the command downloads and executes remote code (curl|sh, wget|bash, etc.).</summary>
    public bool DownloadsAndExecutes { get; init; }
}
