using FluentValidation.TestHelper;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Agent.Validation;

namespace VulcansTrace.Linux.Tests.Agent.Validation;

public sealed class SuppressionEntryValidatorTests
{
    private readonly SuppressionEntryValidator _validator = new();

    [Fact]
    public void ValidEntry_Passes()
    {
        var entry = new SuppressionEntry
        {
            RuleId = "FW-001",
            Target = "SSH/22",
            CreatedAt = DateTime.UtcNow
        };

        var result = _validator.TestValidate(entry);
        result.ShouldNotHaveAnyValidationErrors();
    }

    [Fact]
    public void EmptyRuleId_Fails()
    {
        var entry = new SuppressionEntry
        {
            RuleId = "",
            Target = "SSH/22",
            CreatedAt = DateTime.UtcNow
        };

        var result = _validator.TestValidate(entry);
        result.ShouldHaveValidationErrorFor(x => x.RuleId);
    }

    [Fact]
    public void EmptyTarget_Fails()
    {
        var entry = new SuppressionEntry
        {
            RuleId = "FW-001",
            Target = "   ",
            CreatedAt = DateTime.UtcNow
        };

        var result = _validator.TestValidate(entry);
        result.ShouldHaveValidationErrorFor(x => x.Target);
    }

    [Fact]
    public void NonUtcCreatedAt_Fails()
    {
        var entry = new SuppressionEntry
        {
            RuleId = "FW-001",
            Target = "SSH/22",
            CreatedAt = new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Local)
        };

        var result = _validator.TestValidate(entry);
        result.ShouldHaveValidationErrorFor(x => x.CreatedAt);
    }

    [Fact]
    public void NonUtcExpiresAt_Fails()
    {
        var entry = new SuppressionEntry
        {
            RuleId = "FW-001",
            Target = "SSH/22",
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Unspecified)
        };

        var result = _validator.TestValidate(entry);
        result.ShouldHaveValidationErrorFor(x => x.ExpiresAt);
    }
}
