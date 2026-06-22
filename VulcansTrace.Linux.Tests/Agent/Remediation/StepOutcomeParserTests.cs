using VulcansTrace.Linux.Agent.Remediation;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent.Remediation;

public class StepOutcomeParserTests
{
    private readonly StepOutcomeParser _parser = new();

    [Theory]
    [InlineData("step 1 done", StepOutcomeKind.Success, 1, null)]
    [InlineData("step 2 succeeded", StepOutcomeKind.Success, 2, null)]
    [InlineData("FW-001 done", StepOutcomeKind.Success, null, "FW-001")]
    [InlineData("it worked", StepOutcomeKind.Success, null, null)]
    [InlineData("that worked", StepOutcomeKind.Success, null, null)]
    [InlineData("completed", StepOutcomeKind.Success, null, null)]
    [InlineData("step 2 failed", StepOutcomeKind.Failure, 2, null)]
    [InlineData("step 3 failed with permission denied", StepOutcomeKind.Failure, 3, null)]
    [InlineData("FW-002 failed", StepOutcomeKind.Failure, null, "FW-002")]
    [InlineData("K8S-001 failed", StepOutcomeKind.Failure, null, "K8S-001")]
    [InlineData("pkg-vuln-001 failed", StepOutcomeKind.Failure, null, "PKG-VULN-001")]
    [InlineData("that didn't work", StepOutcomeKind.Failure, null, null)]
    [InlineData("does not work", StepOutcomeKind.Failure, null, null)]
    [InlineData("error: command not found", StepOutcomeKind.Failure, null, null)]
    public void Parse_ReturnsExpectedOutcome(string query, StepOutcomeKind expectedKind, int? expectedOrdinal, string? expectedRuleId)
    {
        var result = _parser.Parse(query);

        Assert.Equal(expectedKind, result.Kind);
        Assert.Equal(expectedOrdinal, result.StepOrdinal);
        Assert.Equal(expectedRuleId, result.RuleId);
    }

    [Fact]
    public void Parse_CapturesFailureReason()
    {
        var result = _parser.Parse("step 2 failed — iptables isn't installed");

        Assert.Equal(StepOutcomeKind.Failure, result.Kind);
        Assert.Equal(2, result.StepOrdinal);
        Assert.Contains("iptables", result.FailureReason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_SuccessReport_HasNoFailureReason()
    {
        var result = _parser.Parse("step 1 done");

        Assert.Equal(StepOutcomeKind.Success, result.Kind);
        Assert.Null(result.FailureReason);
    }

    [Fact]
    public void Parse_EmptyQuery_DefaultsToFailure()
    {
        var result = _parser.Parse("");

        Assert.Equal(StepOutcomeKind.Failure, result.Kind);
        Assert.False(result.HasExplicitReference);
    }
}
