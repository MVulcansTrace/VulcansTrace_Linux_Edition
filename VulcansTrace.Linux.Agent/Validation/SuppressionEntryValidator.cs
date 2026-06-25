using FluentValidation;

namespace VulcansTrace.Linux.Agent.Validation;

/// <summary>
/// Validates a <see cref="Rules.SuppressionEntry"/> before it is persisted or after it is loaded.
/// </summary>
public sealed class SuppressionEntryValidator : AbstractValidator<Rules.SuppressionEntry>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="SuppressionEntryValidator"/> class.
    /// </summary>
    public SuppressionEntryValidator()
    {
        RuleFor(x => x.RuleId).NotEmpty();
        RuleFor(x => x.Target).NotEmpty();
        RuleFor(x => x.CreatedAt).MustBeUtc();
        RuleFor(x => x.ExpiresAt).MustBeUtcWhenPresent();
        RuleFor(x => x.ReviewDate).MustBeUtcWhenPresent();
    }
}
