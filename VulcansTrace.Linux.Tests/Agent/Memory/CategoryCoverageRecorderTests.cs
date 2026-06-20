using VulcansTrace.Linux.Agent.Memory;
using VulcansTrace.Linux.Agent.Query;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent.Memory;

public class CategoryCoverageRecorderTests
{
    private readonly CategoryCoverageRecorder _recorder = new();

    [Fact]
    public void Record_TargetedAudit_AddsCategory()
    {
        var timestamp = new DateTime(2026, 6, 20, 12, 0, 0, DateTimeKind.Utc);

        var coverage = _recorder.Record(AgentIntent.SshCheck, timestamp, Array.Empty<CategoryAuditEntry>());

        Assert.Single(coverage);
        Assert.Contains(coverage, e => e.Category == "SSH" && e.UtcTimestamp == timestamp);
    }

    [Fact]
    public void Record_FullAudit_AddsAllCategories()
    {
        var timestamp = new DateTime(2026, 6, 20, 12, 0, 0, DateTimeKind.Utc);

        var coverage = _recorder.Record(AgentIntent.FullAudit, timestamp, Array.Empty<CategoryAuditEntry>());

        Assert.Equal(IntentCategoryMap.AllCategories.Count, coverage.Count);
        Assert.All(IntentCategoryMap.AllCategories, c =>
            Assert.Contains(coverage, e => e.Category == c && e.UtcTimestamp == timestamp));
    }

    [Fact]
    public void Record_NonAuditIntent_DoesNotChangeCoverage()
    {
        var timestamp = new DateTime(2026, 6, 20, 12, 0, 0, DateTimeKind.Utc);
        var existing = new[] { new CategoryAuditEntry { Category = "SSH", UtcTimestamp = timestamp } };

        var coverage = _recorder.Record(AgentIntent.Help, timestamp, existing);

        Assert.Single(coverage);
    }

    [Fact]
    public void Record_DuplicateCategory_UpdatesTimestamp()
    {
        var firstTimestamp = new DateTime(2026, 6, 20, 10, 0, 0, DateTimeKind.Utc);
        var secondTimestamp = new DateTime(2026, 6, 20, 12, 0, 0, DateTimeKind.Utc);
        var existing = new[] { new CategoryAuditEntry { Category = "SSH", UtcTimestamp = firstTimestamp } };

        var coverage = _recorder.Record(AgentIntent.SshCheck, secondTimestamp, existing);

        Assert.Single(coverage);
        Assert.Equal(secondTimestamp, coverage[0].UtcTimestamp);
    }

    [Fact]
    public void GetUncheckedCategories_WithNoCoverage_ReturnsAllCategories()
    {
        var uncheckedCategories = CategoryCoverageRecorder.GetUncheckedCategories(Array.Empty<CategoryAuditEntry>());

        Assert.Equal(IntentCategoryMap.AllCategories.Count, uncheckedCategories.Count);
    }

    [Fact]
    public void GetUncheckedCategories_WithPartialCoverage_ReturnsRemainingCategories()
    {
        var checkedCategories = new[]
        {
            new CategoryAuditEntry { Category = "SSH" },
            new CategoryAuditEntry { Category = "Firewall" }
        };

        var uncheckedCategories = CategoryCoverageRecorder.GetUncheckedCategories(checkedCategories);

        Assert.DoesNotContain("SSH", uncheckedCategories);
        Assert.DoesNotContain("Firewall", uncheckedCategories);
        Assert.Contains("FilesystemAudit", uncheckedCategories);
        Assert.Contains("ProcessRuntime", uncheckedCategories);
    }

    [Fact]
    public void GetCheckedCategories_ReturnsDistinctAlphabeticalCategories()
    {
        var checkedCategories = new[]
        {
            new CategoryAuditEntry { Category = "SSH" },
            new CategoryAuditEntry { Category = "Firewall" },
            new CategoryAuditEntry { Category = "ssh" }
        };

        var distinctCategories = CategoryCoverageRecorder.GetCheckedCategories(checkedCategories);

        Assert.Equal(2, distinctCategories.Count);
        Assert.Equal("Firewall", distinctCategories[0]);
        Assert.Equal("SSH", distinctCategories[1]);
    }

    [Fact]
    public void Record_TargetedThenFullAudit_MarksAllCategoriesWithFullAuditTimestamp()
    {
        var targetedTime = new DateTime(2026, 6, 20, 10, 0, 0, DateTimeKind.Utc);
        var fullAuditTime = new DateTime(2026, 6, 20, 12, 0, 0, DateTimeKind.Utc);

        var afterTargeted = _recorder.Record(AgentIntent.SshCheck, targetedTime, Array.Empty<CategoryAuditEntry>());
        var afterFullAudit = _recorder.Record(AgentIntent.FullAudit, fullAuditTime, afterTargeted);

        Assert.Equal(IntentCategoryMap.AllCategories.Count, afterFullAudit.Count);
        Assert.All(afterFullAudit, e => Assert.Equal(fullAuditTime, e.UtcTimestamp));
    }

    [Fact]
    public void Record_FullAuditThenTargeted_PreservesAllCategoriesAndUpdatesSingleTimestamp()
    {
        var fullAuditTime = new DateTime(2026, 6, 20, 10, 0, 0, DateTimeKind.Utc);
        var targetedTime = new DateTime(2026, 6, 20, 12, 0, 0, DateTimeKind.Utc);

        var afterFullAudit = _recorder.Record(AgentIntent.FullAudit, fullAuditTime, Array.Empty<CategoryAuditEntry>());
        var afterTargeted = _recorder.Record(AgentIntent.SshCheck, targetedTime, afterFullAudit);

        Assert.Equal(IntentCategoryMap.AllCategories.Count, afterTargeted.Count);
        var ssh = Assert.Single(afterTargeted, e => e.Category == "SSH");
        Assert.Equal(targetedTime, ssh.UtcTimestamp);
        Assert.All(afterTargeted.Where(e => e.Category != "SSH"), e => Assert.Equal(fullAuditTime, e.UtcTimestamp));
    }
}
