using VulcansTrace.Linux.Agent.Extensions;

namespace VulcansTrace.Linux.Tests.Agent;

public sealed class StringExtensionsTests
{
    [Fact]
    public void TruncateWithEllipsis_WhenTruncated_TotalLengthStaysWithinBudget()
    {
        // Regression: the old StixParser.Truncate took `maxLength` chars and THEN
        // appended "...", yielding maxLength + 3. The shared helper must reserve the
        // ellipsis within the budget so the result never exceeds maxLength.
        var longValue = new string('x', 600);

        var truncated = longValue.TruncateWithEllipsis(500);

        Assert.Equal(500, truncated.Length);
        Assert.EndsWith("...", truncated);
        Assert.Equal(new string('x', 497), truncated[..^3]);
    }

    [Fact]
    public void TruncateWithEllipsis_WhenShorterThanBudget_ReturnsInputUnchanged()
    {
        var value = new string('y', 100);

        var result = value.TruncateWithEllipsis(500);

        Assert.Same(value, result);
        Assert.DoesNotContain("...", result);
    }

    [Fact]
    public void TruncateWithEllipsis_AtExactBudget_ReturnsInputUnchanged()
    {
        var value = new string('z', 500);

        var result = value.TruncateWithEllipsis(500);

        Assert.Same(value, result);
    }

    [Fact]
    public void TruncateWithEllipsis_Empty_ReturnsEmpty()
    {
        Assert.Equal(string.Empty, string.Empty.TruncateWithEllipsis(500));
    }

    [Fact]
    public void TruncateWithEllipsis_Null_Throws()
    {
        // Documents the contract: callers must pass non-null (all current call sites
        // pass regex-validated or otherwise non-null strings).
        Assert.Throws<ArgumentNullException>(() => ((string)null!).TruncateWithEllipsis(500));
    }
}
