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

    [Fact]
    public void Calculate_Narrative_OnlyResolved_ReturnsResolvedSentence()
    {
        var before = CreateEntry(new[] { ("FW-001", "A", "High"), ("FW-002", "B", "Medium") });
        var after = CreateEntry(new[] { ("FW-001", "A", "High") });

        var diff = AuditDiffCalculator.Calculate(before, after);

        Assert.Equal("1 finding resolved.", diff.Narrative);
    }

    [Fact]
    public void Calculate_Narrative_NewCritical_CalloutCritical()
    {
        var before = CreateEntry(new[] { ("RULE-001", "A", "High") });
        var after = CreateEntry(new[] { ("RULE-001", "A", "High"), ("PORT-003", "B", "Critical") });

        var diff = AuditDiffCalculator.Calculate(before, after);

        Assert.Equal("1 new Critical finding.", diff.Narrative);
    }

    [Fact]
    public void Calculate_Narrative_MixedSeverities_IncludesBreakdown()
    {
        var before = CreateEntry(new[] { ("RULE-001", "A", "High") });
        var after = CreateEntry(new[]
        {
            ("RULE-001", "A", "High"),
            ("PORT-003", "B", "Critical"),
            ("PORT-002", "C", "High"),
            ("PORT-004", "D", "Low")
        });

        var diff = AuditDiffCalculator.Calculate(before, after);

        Assert.Equal("3 new findings (1 Critical, 1 High).", diff.Narrative);
    }

    [Fact]
    public void Calculate_Narrative_SSHUnchanged_MentionsSSHExposure()
    {
        var before = CreateEntry(new[]
        {
            ("FW-002", "SSH/22", "High"),
            ("FW-001", "A", "High")
        });
        var after = CreateEntry(new[]
        {
            ("FW-002", "SSH/22", "High"),
            ("FW-001", "A", "Medium")
        });

        var diff = AuditDiffCalculator.Calculate(before, after);

        Assert.Equal("1 finding improved, SSH exposure unchanged.", diff.Narrative);
    }

    [Fact]
    public void Calculate_Narrative_NoChanges_ReturnsNoChanges()
    {
        var before = CreateEntry(new[] { ("RULE-001", "A", "High") });
        var after = CreateEntry(new[] { ("RULE-001", "A", "High") });

        var diff = AuditDiffCalculator.Calculate(before, after);

        Assert.Equal("No changes between audits.", diff.Narrative);
    }

    [Fact]
    public void Calculate_Narrative_NoChangesWithStableSsh_ReturnsNoChanges()
    {
        var before = CreateEntry(new[] { ("FW-002", "SSH/22", "High") });
        var after = CreateEntry(new[] { ("FW-002", "SSH/22", "High") });

        var diff = AuditDiffCalculator.Calculate(before, after);

        Assert.Equal("No changes between audits.", diff.Narrative);
    }

    [Fact]
    public void Calculate_Narrative_StableSsh_DoesNotAlsoReportFirewall()
    {
        var before = CreateEntry(new[]
        {
            ("FW-002", "SSH/22", "High"),
            ("RULE-001", "A", "High")
        });
        var after = CreateEntry(new[]
        {
            ("FW-002", "SSH/22", "High"),
            ("RULE-001", "A", "Medium")
        });

        var diff = AuditDiffCalculator.Calculate(before, after);

        Assert.Equal("1 finding improved, SSH exposure unchanged.", diff.Narrative);
    }

    [Fact]
    public void Calculate_Narrative_WorsenedAndImproved_BothMentioned()
    {
        var before = CreateEntry(new[]
        {
            ("FW-001", "A", "Medium"),
            ("FW-002", "B", "High")
        });
        var after = CreateEntry(new[]
        {
            ("FW-001", "A", "High"),
            ("FW-002", "B", "Low")
        });

        var diff = AuditDiffCalculator.Calculate(before, after);

        Assert.Equal("1 finding worsened, 1 finding improved.", diff.Narrative);
    }

    [Fact]
    public void Calculate_Narrative_ResolvedAndNewCritical_WithUnchangedSSH()
    {
        var before = CreateEntry(new[]
        {
            ("FW-002", "SSH/22", "High"),
            ("FW-003", "B", "Medium")
        });
        var after = CreateEntry(new[]
        {
            ("FW-002", "SSH/22", "High"),
            ("PORT-003", "C", "Critical")
        });

        var diff = AuditDiffCalculator.Calculate(before, after);

        Assert.Equal("1 finding resolved, 1 new Critical finding, SSH exposure unchanged.", diff.Narrative);
    }

    [Fact]
    public void Calculate_Narrative_ExposureChanged_DoesNotMentionUnchanged()
    {
        var before = CreateEntry(new[]
        {
            ("FW-002", "SSH/22", "High")
        });
        var after = CreateEntry(new[]
        {
            ("FW-002", "SSH/22", "Critical")
        });

        var diff = AuditDiffCalculator.Calculate(before, after);

        Assert.Equal("1 finding worsened.", diff.Narrative);
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
