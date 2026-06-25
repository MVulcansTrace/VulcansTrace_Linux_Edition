using FluentValidation;
using VulcansTrace.Linux.Agent.Sessions;

namespace VulcansTrace.Linux.Agent.Validation;

/// <summary>
/// Validates a <see cref="RemediationSession"/> before persistence or after loading.
/// </summary>
public sealed class RemediationSessionValidator : AbstractValidator<RemediationSession>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="RemediationSessionValidator"/> class.
    /// </summary>
    public RemediationSessionValidator()
    {
        RuleFor(x => x.SessionId).NotEmpty();
        RuleFor(x => x.CreatedAtUtc).MustBeUtc();
        RuleFor(x => x.SourceFindings).NotNull();
        RuleFor(x => x.RemediationPlan).NotNull();
        RuleFor(x => x.StepStates).NotNull();
        RuleFor(x => x.StepFailureReasons).NotNull();
        RuleFor(x => x.BlockedReasons).NotNull();
        RuleFor(x => x.Timeline).NotNull();
        RuleFor(x => x.Notes).NotNull();

        RuleForEach(x => x.Timeline)
            .SetValidator(new RemediationSessionEventValidator());

        RuleForEach(x => x.Notes)
            .SetValidator(new SessionNoteValidator());

        RuleFor(x => x.BeforeSnapshot)
            .SetValidator(new AuditSnapshotValidator()!)
            .When(x => x.BeforeSnapshot != null);

        RuleFor(x => x.AfterSnapshot)
            .SetValidator(new AuditSnapshotValidator()!)
            .When(x => x.AfterSnapshot != null);

        RuleFor(x => x.VerificationResult)
            .SetValidator(new SessionVerificationResultValidator()!)
            .When(x => x.VerificationResult != null);
    }
}
