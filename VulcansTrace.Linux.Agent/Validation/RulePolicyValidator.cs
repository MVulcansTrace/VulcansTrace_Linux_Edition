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
        RuleFor(x => x.Parameters).NotNull();
    }
}
