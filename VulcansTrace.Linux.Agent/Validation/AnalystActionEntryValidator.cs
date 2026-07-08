using FluentValidation;
using VulcansTrace.Linux.Agent.Validation;

namespace VulcansTrace.Linux.Agent.Actions;

/// <summary>
/// Validates an <see cref="AnalystActionEntry"/> before persistence or after loading.
/// </summary>
public sealed class AnalystActionEntryValidator : AbstractValidator<AnalystActionEntry>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AnalystActionEntryValidator"/> class.
    /// </summary>
    public AnalystActionEntryValidator()
    {
        RuleFor(x => x.Id).NotEmpty();
        RuleFor(x => x.TimestampUtc).MustBeUtc();
        RuleFor(x => x.Actor).NotEmpty();
        RuleFor(x => x.ActionType).NotEmpty();
    }
}
