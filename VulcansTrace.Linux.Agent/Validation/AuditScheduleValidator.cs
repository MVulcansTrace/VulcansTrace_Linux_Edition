using FluentValidation;
using VulcansTrace.Linux.Agent.Scheduling;

namespace VulcansTrace.Linux.Agent.Validation;

/// <summary>
/// Validates an <see cref="AuditSchedule"/> before persistence or after loading.
/// </summary>
public sealed class AuditScheduleValidator : AbstractValidator<AuditSchedule>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AuditScheduleValidator"/> class.
    /// </summary>
    public AuditScheduleValidator()
    {
        RuleFor(x => x.Id).NotEmpty();
        RuleFor(x => x.Name).NotEmpty();
        RuleFor(x => x.CronExpression)
            .NotEmpty()
            .Must(CronExpressionValidator.IsValid)
            .WithMessage("'{PropertyName}' is not a valid 5-field cron expression.");
        RuleFor(x => x.CreatedAtUtc).MustBeUtc();
        RuleFor(x => x.AllowedRemediationRulePrefixes).NotNull();
    }
}
