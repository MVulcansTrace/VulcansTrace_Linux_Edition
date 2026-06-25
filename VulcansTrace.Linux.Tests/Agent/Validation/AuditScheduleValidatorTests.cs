using FluentValidation.TestHelper;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Scheduling;
using VulcansTrace.Linux.Agent.Validation;

namespace VulcansTrace.Linux.Tests.Agent.Validation;

public sealed class AuditScheduleValidatorTests
{
    private readonly AuditScheduleValidator _validator = new();

    [Fact]
    public void ValidSchedule_Passes()
    {
        var schedule = new AuditSchedule
        {
            Id = "sched-1",
            Name = "Weekly Full Audit",
            Intent = AgentIntent.FullAudit,
            CronExpression = "0 6 * * 1"
        };

        var result = _validator.TestValidate(schedule);
        result.ShouldNotHaveAnyValidationErrors();
    }

    [Fact]
    public void EmptyId_Fails()
    {
        var schedule = new AuditSchedule
        {
            Id = "",
            Name = "Weekly Full Audit",
            Intent = AgentIntent.FullAudit,
            CronExpression = "0 6 * * 1"
        };

        var result = _validator.TestValidate(schedule);
        result.ShouldHaveValidationErrorFor(x => x.Id);
    }

    [Fact]
    public void InvalidCronExpression_Fails()
    {
        var schedule = new AuditSchedule
        {
            Id = "sched-1",
            Name = "Bad Cron",
            Intent = AgentIntent.FullAudit,
            CronExpression = "not-a-cron"
        };

        var result = _validator.TestValidate(schedule);
        result.ShouldHaveValidationErrorFor(x => x.CronExpression);
    }

    [Fact]
    public void NonUtcCreatedAt_Fails()
    {
        var schedule = new AuditSchedule
        {
            Id = "sched-1",
            Name = "Weekly Full Audit",
            Intent = AgentIntent.FullAudit,
            CronExpression = "0 6 * * 1",
            CreatedAtUtc = new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Local)
        };

        var result = _validator.TestValidate(schedule);
        result.ShouldHaveValidationErrorFor(x => x.CreatedAtUtc);
    }
}
