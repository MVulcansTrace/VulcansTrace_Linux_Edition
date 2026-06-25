using FluentValidation;
using VulcansTrace.Linux.Agent.Sessions;

namespace VulcansTrace.Linux.Agent.Validation;

/// <summary>
/// Validates a <see cref="SessionVerificationResult"/>.
/// </summary>
public sealed class SessionVerificationResultValidator : AbstractValidator<SessionVerificationResult>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="SessionVerificationResultValidator"/> class.
    /// </summary>
    public SessionVerificationResultValidator()
    {
        RuleFor(x => x.VerifiedAtUtc).MustBeUtc();
        RuleFor(x => x.DiffNarrative).NotNull();
        RuleFor(x => x.FixedFindings).NotNull();
        RuleFor(x => x.UnchangedFindings).NotNull();
        RuleFor(x => x.NewFindings).NotNull();
        RuleFor(x => x.WorsenedFindings).NotNull();
        RuleForEach(x => x.FixedFindings).SetValidator(new AuditSnapshotFindingValidator());
        RuleForEach(x => x.UnchangedFindings).SetValidator(new AuditSnapshotFindingValidator());
        RuleForEach(x => x.NewFindings).SetValidator(new AuditSnapshotFindingValidator());
    }
}
