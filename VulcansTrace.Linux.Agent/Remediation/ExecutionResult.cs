using VulcansTrace.Linux.Agent.Reports;

namespace VulcansTrace.Linux.Agent.Remediation;

/// <summary>
/// The overall result of executing a remediation plan.
/// </summary>
public sealed record RemediationExecutionResult
{
    /// <summary>Whether this was a dry-run (no changes made).</summary>
    public required bool IsDryRun { get; init; }

    /// <summary>UTC timestamp when execution started.</summary>
    public DateTime StartedAtUtc { get; init; } = DateTime.UtcNow;

    /// <summary>UTC timestamp when execution completed.</summary>
    public DateTime CompletedAtUtc { get; init; }

    /// <summary>Results for each section in the plan.</summary>
    public IReadOnlyList<SectionExecutionResult> Sections { get; init; } = Array.Empty<SectionExecutionResult>();

    /// <summary>Total number of commands that would be or were executed.</summary>
    public int TotalCommandsExecuted => Sections.Sum(s => s.CommandsExecuted);

    /// <summary>Total number of commands that failed.</summary>
    public int TotalCommandsFailed => Sections.Sum(s => s.CommandsFailed);

    /// <summary>Total number of sections skipped due to policy or validation.</summary>
    public int SectionsSkipped => Sections.Count(s => s.Skipped);

    /// <summary>Whether all executed commands succeeded.</summary>
    public bool AllSucceeded => Sections.All(s => s.Skipped || s.AllCommandsSucceeded);

    /// <summary>Human-readable summary of the execution.</summary>
    public string Summary { get; init; } = "";
}

/// <summary>
/// The result of executing (or skipping) a single remediation plan section.
/// </summary>
public sealed record SectionExecutionResult
{
    /// <summary>The rule identifier.</summary>
    public required string RuleId { get; init; }

    /// <summary>Brief description of the finding.</summary>
    public required string FindingSummary { get; init; }

    /// <summary>Whether this section was skipped.</summary>
    public bool Skipped { get; init; }

    /// <summary>Reason the section was skipped, if applicable.</summary>
    public string SkipReason { get; init; } = "";

    /// <summary>Results for backup commands.</summary>
    public IReadOnlyList<CommandExecutionResult> BackupResults { get; init; } = Array.Empty<CommandExecutionResult>();

    /// <summary>Results for apply commands.</summary>
    public IReadOnlyList<CommandExecutionResult> ApplyResults { get; init; } = Array.Empty<CommandExecutionResult>();

    /// <summary>Results for verification commands.</summary>
    public IReadOnlyList<CommandExecutionResult> VerificationResults { get; init; } = Array.Empty<CommandExecutionResult>();

    /// <summary>Results for rollback commands executed after apply failure.</summary>
    public IReadOnlyList<CommandExecutionResult> RollbackResults { get; init; } = Array.Empty<CommandExecutionResult>();

    /// <summary>Number of commands that were executed (not skipped).</summary>
    public int CommandsExecuted => BackupResults.Count(r => !r.Skipped)
        + ApplyResults.Count(r => !r.Skipped)
        + VerificationResults.Count(r => !r.Skipped)
        + RollbackResults.Count(r => !r.Skipped);

    /// <summary>Number of commands that failed.</summary>
    public int CommandsFailed => BackupResults.Count(r => !r.Skipped && !r.Success)
        + ApplyResults.Count(r => !r.Skipped && !r.Success)
        + VerificationResults.Count(r => !r.Skipped && !r.Success)
        + RollbackResults.Count(r => !r.Skipped && !r.Success);

    /// <summary>Whether all non-skipped commands succeeded.</summary>
    public bool AllCommandsSucceeded => BackupResults.All(r => r.Skipped || r.Success)
        && ApplyResults.All(r => r.Skipped || r.Success)
        && VerificationResults.All(r => r.Skipped || r.Success)
        && RollbackResults.All(r => r.Skipped || r.Success);
}

/// <summary>
/// The result of executing a single command.
/// </summary>
public sealed record CommandExecutionResult
{
    /// <summary>The command text.</summary>
    public required string Command { get; init; }

    /// <summary>Phase this command belongs to.</summary>
    public required RemediationPhase Phase { get; init; }

    /// <summary>Whether this command was skipped due to policy.</summary>
    public bool Skipped { get; init; }

    /// <summary>Reason the command was skipped, if applicable.</summary>
    public string SkipReason { get; init; } = "";

    /// <summary>Whether the command executed successfully (exit code 0).</summary>
    public bool Success { get; init; }

    /// <summary>The process exit code.</summary>
    public int ExitCode { get; init; }

    /// <summary>Standard output.</summary>
    public string StdOut { get; init; } = "";

    /// <summary>Standard error.</summary>
    public string StdErr { get; init; } = "";

    /// <summary>Elapsed time for execution.</summary>
    public TimeSpan Elapsed { get; init; }
}

/// <summary>
/// Describes which phase of remediation a command belongs to.
/// </summary>
public enum RemediationPhase
{
    /// <summary>Command preserves state before changes.</summary>
    Backup,

    /// <summary>Command applies the fix.</summary>
    Apply,

    /// <summary>Command confirms the fix worked.</summary>
    Verify,

    /// <summary>Command undoes changes after an apply failure.</summary>
    Rollback
}
