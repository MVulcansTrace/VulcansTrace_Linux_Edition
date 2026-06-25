using FluentValidation;
using VulcansTrace.Linux.Agent.Reports;

namespace VulcansTrace.Linux.Agent.Validation;

/// <summary>
/// Validates an <see cref="AuditSnapshotFinding"/>.
/// </summary>
public sealed class AuditSnapshotFindingValidator : AbstractValidator<AuditSnapshotFinding>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AuditSnapshotFindingValidator"/> class.
    /// </summary>
    public AuditSnapshotFindingValidator()
    {
        RuleFor(x => x.RuleId).NotEmpty();
        RuleFor(x => x.Target).NotEmpty();
        RuleFor(x => x.Severity).NotEmpty();
        RuleFor(x => x.Confidence).NotEmpty();
        RuleFor(x => x.ShortDescription).NotEmpty();
        RuleFor(x => x.EvidenceSignals).NotNull();
        RuleFor(x => x.RepresentativeTargets).NotNull();
        RuleFor(x => x.RiskDrivers).NotNull();
        RuleFor(x => x.GroupedCount).GreaterThanOrEqualTo(1);
    }
}
