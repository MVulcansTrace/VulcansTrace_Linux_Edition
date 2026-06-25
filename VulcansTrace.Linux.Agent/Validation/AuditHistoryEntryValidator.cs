using FluentValidation;
using VulcansTrace.Linux.Agent.Reports;

namespace VulcansTrace.Linux.Agent.Validation;

/// <summary>
/// Validates an <see cref="AuditHistoryEntry"/> before persistence or after loading.
/// </summary>
public sealed class AuditHistoryEntryValidator : AbstractValidator<AuditHistoryEntry>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AuditHistoryEntryValidator"/> class.
    /// </summary>
    public AuditHistoryEntryValidator()
    {
        RuleFor(x => x.SnapshotId).NotEmpty();
        RuleFor(x => x.TimestampUtc).MustBeUtc();
        RuleFor(x => x.TotalFindings).GreaterThanOrEqualTo(0);
        RuleFor(x => x.CriticalCount).GreaterThanOrEqualTo(0);
        RuleFor(x => x.HighCount).GreaterThanOrEqualTo(0);
        RuleFor(x => x.MediumCount).GreaterThanOrEqualTo(0);
        RuleFor(x => x.LowCount).GreaterThanOrEqualTo(0);
        RuleFor(x => x.InfoCount).GreaterThanOrEqualTo(0);
        RuleFor(x => x.WarningCount).GreaterThanOrEqualTo(0);
        RuleFor(x => x.PassedCount).GreaterThanOrEqualTo(0);
        RuleFor(x => x.FailedCount).GreaterThanOrEqualTo(0);
        RuleFor(x => x.SuppressedCount).GreaterThanOrEqualTo(0);
        RuleFor(x => x.CrashedCount).GreaterThanOrEqualTo(0);
        RuleFor(x => x.SnapshotFindings).NotNull();
        RuleFor(x => x.DataSourceCapabilities).NotNull();
        RuleFor(x => x.AttackChains).NotNull();
        RuleFor(x => x.RuleResults).NotNull();
        RuleFor(x => x.Warnings).NotNull();

        RuleForEach(x => x.SnapshotFindings)
            .SetValidator(new AuditSnapshotFindingValidator());
    }
}
