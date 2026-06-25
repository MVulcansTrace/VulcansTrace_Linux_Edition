using FluentValidation;
using VulcansTrace.Linux.Agent.Sessions;

namespace VulcansTrace.Linux.Agent.Validation;

/// <summary>
/// Validates an <see cref="AuditSnapshot"/>.
/// </summary>
public sealed class AuditSnapshotValidator : AbstractValidator<AuditSnapshot>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AuditSnapshotValidator"/> class.
    /// </summary>
    public AuditSnapshotValidator()
    {
        RuleFor(x => x.TimestampUtc).MustBeUtc();
        RuleFor(x => x.Findings).NotNull();
        RuleForEach(x => x.Findings)
            .SetValidator(new AuditSnapshotFindingValidator());
    }
}
