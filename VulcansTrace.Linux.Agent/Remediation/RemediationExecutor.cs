using System.Diagnostics;
using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Reports;

namespace VulcansTrace.Linux.Agent.Remediation;

/// <summary>
/// Orchestrates the execution of a <see cref="RemediationPlan"/> with dry-run support,
/// safety policy enforcement, and sequential backup/apply/verify phases.
/// </summary>
public sealed class RemediationExecutor
{
    private readonly IProcessRunner _processRunner;
    private readonly TimeSpan _commandTimeout;

    /// <summary>
    /// Initializes a new instance of the <see cref="RemediationExecutor"/> class.
    /// </summary>
    /// <param name="processRunner">The process runner to use for command execution.</param>
    /// <param name="commandTimeout">Maximum time to wait for each command. Defaults to 60 seconds.</param>
    public RemediationExecutor(IProcessRunner processRunner, TimeSpan? commandTimeout = null)
    {
        _processRunner = processRunner ?? throw new ArgumentNullException(nameof(processRunner));
        _commandTimeout = commandTimeout ?? TimeSpan.FromSeconds(60);
        if (_commandTimeout <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(commandTimeout), "Command timeout must be positive.");
    }

    /// <summary>
    /// Executes (or previews) a remediation plan according to the specified policy.
    /// </summary>
    /// <param name="plan">The remediation plan to execute.</param>
    /// <param name="policy">The safety policy governing which commands may run.</param>
    /// <param name="dryRun">If true, no commands are executed; results show what would happen.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The execution result.</returns>
    public async Task<RemediationExecutionResult> ExecuteAsync(
        RemediationPlan plan,
        AutoFixPolicy policy,
        bool dryRun = false,
        CancellationToken ct = default)
    {
        var sectionResults = new List<SectionExecutionResult>();
        var validation = RemediationPlanValidator.Validate(plan);

        foreach (var section in plan.Sections)
        {
            ct.ThrowIfCancellationRequested();
            var sectionResult = await ExecuteSectionAsync(section, policy, validation, dryRun, ct);
            sectionResults.Add(sectionResult);

            // If any apply command failed, stop processing further sections
            // to prevent cascading failures on a potentially broken system state.
            if (!dryRun && sectionResult.ApplyResults.Any(r => !r.Skipped && !r.Success))
            {
                break;
            }
        }

        var completedAt = DateTime.UtcNow;
        var summary = BuildSummary(sectionResults, dryRun);

        return new RemediationExecutionResult
        {
            IsDryRun = dryRun,
            CompletedAtUtc = completedAt,
            Sections = sectionResults,
            Summary = summary
        };
    }

    private async Task<SectionExecutionResult> ExecuteSectionAsync(
        RemediationSection section,
        AutoFixPolicy policy,
        ValidationResult validation,
        bool dryRun,
        CancellationToken ct)
    {
        // Policy: skip sections that fail validation when validation is required
        if (policy.RequireValidation && !validation.IsValid)
        {
            var sectionErrors = validation.Errors.Where(e => e.StartsWith($"[{section.RuleId}]", StringComparison.Ordinal)).ToList();
            if (sectionErrors.Count > 0)
            {
                return new SectionExecutionResult
                {
                    RuleId = section.RuleId,
                    FindingSummary = section.FindingSummary,
                    Skipped = true,
                    SkipReason = $"Validation failed: {string.Join("; ", sectionErrors)}"
                };
            }
        }

        // Policy: skip sections without rollback guidance when required
        if (policy.RequireRollbackGuidance && !section.HasExplicitRollbackGuidance)
        {
            var hasRisky = section.ApplyCommands.Any(c => IsRisky(c.Safety));
            if (hasRisky)
            {
                return new SectionExecutionResult
                {
                    RuleId = section.RuleId,
                    FindingSummary = section.FindingSummary,
                    Skipped = true,
                    SkipReason = "Section lacks explicit rollback guidance and contains risky commands."
                };
            }
        }

        // Execute backup commands first
        var backupResults = new List<CommandExecutionResult>();
        foreach (var cmd in section.BackupCommands)
        {
            backupResults.Add(await ExecuteCommandAsync(cmd, RemediationPhase.Backup, policy, dryRun, ct));
        }

        // If any backup failed (and wasn't skipped), don't apply changes
        var criticalBackupFailure = backupResults.Any(r => !r.Skipped && !r.Success);
        if (criticalBackupFailure && !dryRun)
        {
            return new SectionExecutionResult
            {
                RuleId = section.RuleId,
                FindingSummary = section.FindingSummary,
                BackupResults = backupResults,
                Skipped = true,
                SkipReason = "Backup failed — apply commands were aborted to prevent unsafe changes."
            };
        }

        // Execute apply commands
        var applyResults = new List<CommandExecutionResult>();
        foreach (var cmd in section.ApplyCommands)
        {
            applyResults.Add(await ExecuteCommandAsync(cmd, RemediationPhase.Apply, policy, dryRun, ct));
        }

        // Execute rollback commands if any apply command failed.
        // Rollback is defensive — it undoes changes the policy already permitted —
        // so we bypass the normal policy gate to avoid leaving the system inconsistent.
        var rollbackResults = new List<CommandExecutionResult>();
        var applyFailed = !dryRun && applyResults.Any(r => !r.Skipped && !r.Success);
        if (applyFailed)
        {
            foreach (var cmd in section.RollbackCommands)
            {
                rollbackResults.Add(await ExecuteCommandAsync(cmd, RemediationPhase.Rollback, policy, dryRun, ct, bypassPolicy: true));
            }
        }

        // Execute verification commands only if apply commands succeeded (or in dry-run).
        // Guard against empty apply lists (vacuous All) and all-skipped apply commands
        // — verification against an unchanged system is misleading.
        var verificationResults = new List<CommandExecutionResult>();
        var hadApplicableChanges = applyResults.Any(r => !r.Skipped);
        var applySucceeded = dryRun || (hadApplicableChanges && applyResults.All(r => r.Skipped || r.Success));
        if (applySucceeded)
        {
            foreach (var cmd in section.VerificationCommands)
            {
                verificationResults.Add(await ExecuteCommandAsync(cmd, RemediationPhase.Verify, policy, dryRun, ct));
            }
        }

        return new SectionExecutionResult
        {
            RuleId = section.RuleId,
            FindingSummary = section.FindingSummary,
            BackupResults = backupResults,
            ApplyResults = applyResults,
            VerificationResults = verificationResults,
            RollbackResults = rollbackResults
        };
    }

    private async Task<CommandExecutionResult> ExecuteCommandAsync(
        RemediationCommand cmd,
        RemediationPhase phase,
        AutoFixPolicy policy,
        bool dryRun,
        CancellationToken ct,
        bool bypassPolicy = false)
    {
        ct.ThrowIfCancellationRequested();

        if (!bypassPolicy && !policy.IsPermitted(cmd.Safety))
        {
            return new CommandExecutionResult
            {
                Command = cmd.Command,
                Phase = phase,
                Skipped = true,
                SkipReason = $"Policy blocks {cmd.Safety} commands."
            };
        }

        if (dryRun)
        {
            return new CommandExecutionResult
            {
                Command = cmd.Command,
                Phase = phase,
                Skipped = true,
                SkipReason = "Dry-run mode — no changes made.",
                Success = true // Conceptually succeeds in dry-run
            };
        }

        var sw = Stopwatch.StartNew();
        try
        {
            var result = await _processRunner.RunAsync(cmd.Command, _commandTimeout, ct);
            sw.Stop();

            return new CommandExecutionResult
            {
                Command = cmd.Command,
                Phase = phase,
                Success = result.Success,
                ExitCode = result.ExitCode,
                StdOut = result.StdOut,
                StdErr = result.StdErr,
                Elapsed = sw.Elapsed
            };
        }
        catch (OperationCanceledException)
        {
            throw; // Cancellation must propagate.
        }
        catch (Exception ex)
        {
            sw.Stop();
            return new CommandExecutionResult
            {
                Command = cmd.Command,
                Phase = phase,
                Success = false,
                ExitCode = -1,
                StdErr = $"ProcessRunner threw an unexpected exception: {ex.Message}",
                Elapsed = sw.Elapsed
            };
        }
    }

    private static bool IsRisky(CommandSafety safety) => RemediationPlanValidator.RequiresRollbackGuardrail(safety);

    private static string BuildSummary(List<SectionExecutionResult> sections, bool dryRun)
    {
        var executed = sections.Sum(s => s.CommandsExecuted);
        var failed = sections.Sum(s => s.CommandsFailed);
        var skippedSections = sections.Count(s => s.Skipped);

        var prefix = dryRun ? "[DRY-RUN] " : "";
        if (skippedSections == sections.Count && sections.Count > 0)
        {
            return $"{prefix}All {sections.Count} section(s) were skipped due to policy or validation.";
        }

        var parts = new List<string>
        {
            $"{prefix}Processed {sections.Count} section(s)."
        };

        if (executed > 0)
            parts.Add($"Commands executed: {executed}.");
        if (failed > 0)
            parts.Add($"Commands failed: {failed}.");
        if (skippedSections > 0)
            parts.Add($"Sections skipped: {skippedSections}.");

        return string.Join(" ", parts);
    }
}
