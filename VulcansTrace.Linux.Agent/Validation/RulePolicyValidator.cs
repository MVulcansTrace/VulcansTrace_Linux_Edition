using FluentValidation;

namespace VulcansTrace.Linux.Agent.Validation;

/// <summary>
/// Validates a <see cref="Rules.RulePolicy"/> before persistence or after loading.
/// </summary>
public sealed class RulePolicyValidator : AbstractValidator<Rules.RulePolicy>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="RulePolicyValidator"/> class.
    /// </summary>
    public RulePolicyValidator()
    {
        // Parameters must always be present (the record defaults to an empty dictionary; a
        // hand-edited file could null it out).
        RuleFor(x => x.Parameters).NotNull();

        // JsonStringEnumConverter()'s parameterless constructor allows integer values, so a
        // hand-edited "severityOverride": 999 deserializes to an undefined (Severity)999 and would
        // otherwise flow unchecked into a finding's Severity. Reject undefined severities here so
        // the load path quarantines the file instead of honoring a bogus override.
        RuleFor(x => x.SeverityOverride)
            .Must(v => !v.HasValue || Enum.IsDefined(v.Value))
            .WithMessage("'SeverityOverride' must be a defined severity value.");
    }
}
