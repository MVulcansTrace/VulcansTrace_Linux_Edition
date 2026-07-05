using FluentValidation;

namespace VulcansTrace.Linux.Agent.Validation;

/// <summary>
/// Validates a <see cref="Findings.PinnedFinding"/> before it is persisted or after it is loaded.
/// </summary>
public sealed class PinnedFindingValidator : AbstractValidator<Findings.PinnedFinding>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PinnedFindingValidator"/> class.
    /// </summary>
    public PinnedFindingValidator()
    {
        RuleFor(x => x.Fingerprint).NotEmpty().MaximumLength(512);
        RuleFor(x => x.Category).NotEmpty().MaximumLength(200);
        RuleFor(x => x.Severity).NotEmpty().MaximumLength(50);
        RuleFor(x => x.SourceHost).NotEmpty().MaximumLength(500);
        RuleFor(x => x.Target).NotEmpty().MaximumLength(500);
        RuleFor(x => x.ShortDescription).NotEmpty().MaximumLength(1000);
        RuleFor(x => x.Notes).MaximumLength(4000);
        RuleFor(x => x.PinnedAtUtc).MustBeUtc();
    }
}
