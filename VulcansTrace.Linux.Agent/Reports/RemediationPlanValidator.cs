using VulcansTrace.Linux.Agent.Explanations;

namespace VulcansTrace.Linux.Agent.Reports;

/// <summary>
/// Validates a <see cref="RemediationPlan"/> to ensure risky or unclassified
/// apply/backup commands are accompanied by explicit rollback guidance.
/// </summary>
public static class RemediationPlanValidator
{
    /// <summary>
    /// Validates the remediation plan against guardrail rules.
    /// </summary>
    /// <param name="plan">The plan to validate.</param>
    /// <returns>A <see cref="ValidationResult"/> indicating whether the plan is exportable.</returns>
    public static ValidationResult Validate(RemediationPlan plan)
    {
        var errors = new List<string>();

        foreach (var section in plan.Sections)
        {
            var riskyCommands = section.ApplyCommands
                .Concat(section.BackupCommands)
                .Where(c => RequiresRollbackGuardrail(c.Safety))
                .ToList();

            if (riskyCommands.Count > 0 && !section.HasExplicitRollbackGuidance && section.RollbackCommands.Count == 0)
            {
                errors.Add($"[{section.RuleId}] {section.FindingSummary}: {riskyCommands.Count} risky or unclassified command(s) lack explicit rollback guidance.");
            }
        }

        return errors.Count == 0
            ? ValidationResult.Valid()
            : ValidationResult.Invalid(errors);
    }

    private static bool RequiresRollbackGuardrail(CommandSafety safety)
    {
        return safety is CommandSafety.ConfigChange
            or CommandSafety.PackageInstall
            or CommandSafety.ServiceRestart
            or CommandSafety.Destructive
            or CommandSafety.Unknown;
    }
}

/// <summary>
/// The result of validating a remediation plan.
/// </summary>
public sealed record ValidationResult
{
    /// <summary>Whether the plan passed all guardrail checks.</summary>
    public bool IsValid { get; init; }

    /// <summary>Human-readable error messages for each failed check.</summary>
    public IReadOnlyList<string> Errors { get; init; } = Array.Empty<string>();

    /// <summary>Creates a successful validation result.</summary>
    public static ValidationResult Valid() => new() { IsValid = true };

    /// <summary>Creates a failed validation result with the specified errors.</summary>
    public static ValidationResult Invalid(IEnumerable<string> errors) => new() { IsValid = false, Errors = errors.ToList() };
}
