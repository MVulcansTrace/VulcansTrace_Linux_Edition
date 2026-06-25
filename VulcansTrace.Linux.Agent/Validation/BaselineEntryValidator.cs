using FluentValidation;

namespace VulcansTrace.Linux.Agent.Validation;

/// <summary>
/// Validates a <see cref="Baselines.BaselineEntry"/> before persistence or after loading.
/// </summary>
public sealed class BaselineEntryValidator : AbstractValidator<Baselines.BaselineEntry>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="BaselineEntryValidator"/> class.
    /// </summary>
    public BaselineEntryValidator()
    {
        RuleFor(x => x.BaselineId).NotEmpty();
        RuleFor(x => x.Name).NotEmpty();
        RuleFor(x => x.CreatedUtc).MustBeUtc();
        RuleFor(x => x.TotalFindings).GreaterThanOrEqualTo(0);
        RuleFor(x => x.CriticalCount).GreaterThanOrEqualTo(0);
        RuleFor(x => x.HighCount).GreaterThanOrEqualTo(0);
        RuleFor(x => x.MediumCount).GreaterThanOrEqualTo(0);
        RuleFor(x => x.LowCount).GreaterThanOrEqualTo(0);
        RuleFor(x => x.InfoCount).GreaterThanOrEqualTo(0);
        RuleFor(x => x.SnapshotFindings).NotNull();
        RuleFor(x => x.OriginalFindings).NotNull();
    }
}
