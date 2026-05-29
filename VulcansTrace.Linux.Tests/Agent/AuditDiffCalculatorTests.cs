using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class AuditDiffCalculatorTests
{
    [Fact]
    public void Calculate_NewFinding_Appears_In_New()
    {
        var before = CreateEntry(new[] { ("FW-001", "A", "High") });
        var after = CreateEntry(new[] { ("FW-001", "A", "High"), ("FW-002", "B", "Medium") });

        var diff = AuditDiffCalculator.Calculate(before, after);

        Assert.Single(diff.NewFindings);
        Assert.Equal("FW-002", diff.NewFindings[0].RuleId);
        Assert.Empty(diff.ResolvedFindings);
        Assert.Empty(diff.WorsenedFindings);
        Assert.Empty(diff.ImprovedFindings);
    }

    [Fact]
    public void Calculate_ResolvedFinding_Appears_In_Resolved()
    {
        var before = CreateEntry(new[] { ("FW-001", "A", "High"), ("FW-002", "B", "Medium") });
        var after = CreateEntry(new[] { ("FW-001", "A", "High") });

        var diff = AuditDiffCalculator.Calculate(before, after);

        Assert.Single(diff.ResolvedFindings);
        Assert.Equal("FW-002", diff.ResolvedFindings[0].RuleId);
        Assert.Empty(diff.NewFindings);
    }

    [Fact]
    public void Calculate_WorsenedSeverity_Detected()
    {
        var before = CreateEntry(new[] { ("FW-001", "A", "Medium") });
        var after = CreateEntry(new[] { ("FW-001", "A", "High") });

        var diff = AuditDiffCalculator.Calculate(before, after);

        Assert.Single(diff.WorsenedFindings);
        Assert.Equal("Medium", diff.WorsenedFindings[0].OldSeverity);
        Assert.Equal("High", diff.WorsenedFindings[0].NewSeverity);
    }

    [Fact]
    public void Calculate_ImprovedSeverity_Detected()
    {
        var before = CreateEntry(new[] { ("FW-001", "A", "High") });
        var after = CreateEntry(new[] { ("FW-001", "A", "Low") });

        var diff = AuditDiffCalculator.Calculate(before, after);

        Assert.Single(diff.ImprovedFindings);
        Assert.Equal("High", diff.ImprovedFindings[0].OldSeverity);
        Assert.Equal("Low", diff.ImprovedFindings[0].NewSeverity);
    }

    [Fact]
    public void Calculate_Unchanged_Findings_Listed()
    {
        var before = CreateEntry(new[] { ("FW-001", "A", "High") });
        var after = CreateEntry(new[] { ("FW-001", "A", "High") });

        var diff = AuditDiffCalculator.Calculate(before, after);

        Assert.Single(diff.UnchangedFindings);
        Assert.Empty(diff.NewFindings);
        Assert.Empty(diff.ResolvedFindings);
    }

    [Fact]
    public void Calculate_Summary_Is_Accurate()
    {
        var before = CreateEntry(new[] { ("FW-001", "A", "Medium") });
        var after = CreateEntry(new[] { ("FW-001", "A", "High"), ("FW-002", "B", "Low") });

        var diff = AuditDiffCalculator.Calculate(before, after);

        Assert.Equal("1 new, 0 resolved, 1 worsened, 0 improved.", diff.Summary);
    }

    private static AuditHistoryEntry CreateEntry((string RuleId, string Target, string Severity)[] findings)
    {
        return new AuditHistoryEntry
        {
            SnapshotId = Guid.NewGuid().ToString(),
            Intent = VulcansTrace.Linux.Agent.Query.AgentIntent.FullAudit,
            SnapshotFindings = findings.Select(f => new AuditSnapshotFinding
            {
                RuleId = f.RuleId,
                Target = f.Target,
                Severity = f.Severity,
                ShortDescription = "Test"
            }).ToList()
        };
    }
}
