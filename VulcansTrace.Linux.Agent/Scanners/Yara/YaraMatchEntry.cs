namespace VulcansTrace.Linux.Agent.Scanners;

/// <summary>
/// A single YARA rule match discovered by the <see cref="YaraScanner"/>.
/// </summary>
public sealed record YaraMatchEntry
{
    /// <summary>Path scanned by YARA. Running process targets use /proc/&lt;pid&gt;/exe.</summary>
    public string TargetPath { get; init; } = string.Empty;

    /// <summary>Resolved filesystem path for display when different from <see cref="TargetPath"/>.</summary>
    public string ResolvedTargetPath { get; init; } = string.Empty;

    /// <summary>Kind of target that was scanned (SUID/SGID binary, running process, cron script).</summary>
    public string TargetKind { get; init; } = string.Empty;

    /// <summary>The YARA rule identifier that matched.</summary>
    public string RuleIdentifier { get; init; } = string.Empty;

    /// <summary>Process ID when the target is a running process; otherwise null.</summary>
    public int? ProcessId { get; init; }

    /// <summary>Optional human-readable detail about the match (e.g., rule description or matched offset).</summary>
    public string MatchDescription { get; init; } = string.Empty;
}
