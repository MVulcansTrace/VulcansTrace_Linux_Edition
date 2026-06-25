using FluentValidation;
using VulcansTrace.Linux.Agent.Sessions;

namespace VulcansTrace.Linux.Agent.Validation;

/// <summary>
/// Validates a <see cref="RemediationSessionEvent"/>.
/// </summary>
public sealed class RemediationSessionEventValidator : AbstractValidator<RemediationSessionEvent>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="RemediationSessionEventValidator"/> class.
    /// </summary>
    public RemediationSessionEventValidator()
    {
        RuleFor(x => x.TimestampUtc).MustBeUtc();
        RuleFor(x => x.Title).NotEmpty();
    }
}
