using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Core.Compliance;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class ComplianceScorecardBuilderTests
{
    private readonly ComplianceScorecardBuilder _builder = new();

    [Fact]
    public void Build_EmptyRuleResults_ReturnsNull()
    {
        var scorecard = _builder.Build(Array.Empty<RuleResult>());
        Assert.Null(scorecard);
    }

    [Fact]
    public void Build_NullRuleResults_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => _builder.Build(null!));
    }

    [Fact]
    public void Build_NoCisMappings_ReturnsNull()
    {
        var results = new[]
        {
            RuleResult.Pass("FW-001", "Firewall", "FW-001", "Firewall active")
        };

        var scorecard = _builder.Build(results);

        Assert.Null(scorecard);
    }

    [Fact]
    public void Build_AllHistoryScorecardsNull_ReturnsEmptyTrend()
    {
        var history = new InMemoryAuditHistoryStore();
        history.Append(new AuditHistoryEntry
        {
            SnapshotId = "a",
            TimestampUtc = DateTime.UtcNow.AddDays(-2),
            Intent = AgentIntent.FullAudit,
            Scorecard = null
        });
        history.Append(new AuditHistoryEntry
        {
            SnapshotId = "b",
            TimestampUtc = DateTime.UtcNow.AddDays(-1),
            Intent = AgentIntent.FullAudit,
            Scorecard = null
        });

        var results = new[] { PassWithCis("FW-001", "4.1") };
        var scorecard = _builder.Build(results, history);

        Assert.NotNull(scorecard);
        Assert.Empty(scorecard.Trend);
    }

    [Fact]
    public void Build_AllNotApplicable_ReturnsNull()
    {
        var results = new[]
        {
            new RuleResult
            {
                RuleId = "FW-001",
                Category = "Firewall",
                Passed = true,
                Status = RuleStatus.NotApplicable,
                ExplanationKey = "FW-001",
                Description = "N/A rule",
                CisMappings = new[]
                {
                    new CisBenchmarkMapping { ControlId = "CIS 4.1", ControlName = "Test", WhyItMatters = "M" }
                }
            }
        };

        var scorecard = _builder.Build(results);
        Assert.Null(scorecard);
    }

    [Fact]
    public void Build_UnparseableControlId_ReturnsNull()
    {
        var results = new[]
        {
            new RuleResult
            {
                RuleId = "FW-001",
                Category = "Firewall",
                Passed = true,
                ExplanationKey = "FW-001",
                Description = "Rule with bad CIS id",
                CisMappings = new[]
                {
                    new CisBenchmarkMapping { ControlId = "NIST 4.1", ControlName = "Test", WhyItMatters = "M" }
                }
            }
        };

        var scorecard = _builder.Build(results);
        Assert.Null(scorecard);
    }

    [Fact]
    public void Build_UnknownFamilyNumber_ResolvesToOther()
    {
        var results = new[]
        {
            PassWithCis("FW-001", "10.1")
        };

        var scorecard = _builder.Build(results);

        Assert.NotNull(scorecard);
        Assert.Single(scorecard.FamilyScores);
        Assert.Equal("10", scorecard.FamilyScores[0].FamilyId);
        Assert.Equal("Other", scorecard.FamilyScores[0].FamilyName);
        Assert.Equal(100.0, scorecard.FamilyScores[0].ScorePercentage);
    }

    [Fact]
    public void Build_HistoryWithNullScorecards_SkipsEntries()
    {
        var history = new InMemoryAuditHistoryStore();
        history.Append(new AuditHistoryEntry
        {
            SnapshotId = "a",
            TimestampUtc = DateTime.UtcNow.AddDays(-2),
            Intent = AgentIntent.FullAudit,
            Scorecard = null
        });
        history.Append(new AuditHistoryEntry
        {
            SnapshotId = "b",
            TimestampUtc = DateTime.UtcNow.AddDays(-1),
            Intent = AgentIntent.FullAudit,
            Scorecard = new ComplianceScorecard
            {
                OverallScore = 75.0,
                SummaryStatus = "Warn",
                FamilyScores = Array.Empty<ControlFamilyScore>()
            }
        });

        var results = new[] { PassWithCis("FW-001", "4.1") };
        var scorecard = _builder.Build(results, history);

        Assert.NotNull(scorecard);
        Assert.Single(scorecard.Trend);
        Assert.Equal(75.0, scorecard.Trend[0].OverallScore);
    }

    [Fact]
    public void Build_AllPass_ReturnsPassStatus()
    {
        var results = new[]
        {
            PassWithCis("FW-001", "4.1"),
            PassWithCis("FW-002", "4.2")
        };

        var scorecard = _builder.Build(results);

        Assert.NotNull(scorecard);
        Assert.Equal(100.0, scorecard.OverallScore);
        Assert.Equal("Pass", scorecard.SummaryStatus);
        Assert.Single(scorecard.FamilyScores);
        Assert.Equal("Pass", scorecard.FamilyScores[0].Status);
        Assert.Equal(2, scorecard.FamilyScores[0].TotalControls);
        Assert.Equal(2, scorecard.FamilyScores[0].PassedControls);
    }

    [Fact]
    public void Build_MixedResults_CalculatesCorrectScores()
    {
        var results = new[]
        {
            PassWithCis("FW-001", "4.1"),
            FailWithCis("FW-002", "4.2"),
            PassWithCis("FW-003", "4.3"),
            PassWithCis("FW-004", "4.4"),
            FailWithCis("FW-005", "4.5")
        };

        var scorecard = _builder.Build(results);

        Assert.NotNull(scorecard);
        Assert.Equal(60.0, scorecard.OverallScore);
        Assert.Equal("Fail", scorecard.SummaryStatus);
        Assert.Equal("Fail", scorecard.FamilyScores[0].Status);
        Assert.Equal(3, scorecard.FamilyScores[0].PassedControls);
        Assert.Equal(2, scorecard.FamilyScores[0].FailedControls);
    }

    [Fact]
    public void Build_CrashedRule_ReturnsFail()
    {
        var results = new[]
        {
            PassWithCis("FW-001", "4.1"),
            CrashWithCis("FW-002", "4.2")
        };

        var scorecard = _builder.Build(results);

        Assert.NotNull(scorecard);
        Assert.Equal("Fail", scorecard.SummaryStatus);
        Assert.Equal("Fail", scorecard.FamilyScores[0].Status);
        Assert.Equal(1, scorecard.FamilyScores[0].CrashedControls);
    }

    [Fact]
    public void Build_WarnThreshold_ReturnsWarn()
    {
        var results = new[]
        {
            PassWithCis("FW-001", "4.1"),
            PassWithCis("FW-002", "4.2"),
            PassWithCis("FW-003", "4.3"),
            PassWithCis("FW-004", "4.4"),
            FailWithCis("FW-005", "4.5")
        };

        var scorecard = _builder.Build(results);

        Assert.NotNull(scorecard);
        Assert.Equal(80.0, scorecard.OverallScore);
        Assert.Equal("Warn", scorecard.SummaryStatus);
        Assert.Equal("Warn", scorecard.FamilyScores[0].Status);
    }

    [Fact]
    public void Build_RoundedScore_MatchesThreshold()
    {
        // 7995 / 10000 = 79.95% -> rounds to 80.0% -> Warn (not Fail)
        var results = new List<RuleResult>();
        for (int i = 0; i < 7995; i++)
            results.Add(PassWithCis($"FW-{i:0000}", "4.1"));
        for (int i = 0; i < 2005; i++)
            results.Add(FailWithCis($"FW-F{i:0000}", "4.1"));

        var scorecard = _builder.Build(results);

        Assert.NotNull(scorecard);
        Assert.Equal(80.0, scorecard.OverallScore);
        Assert.Equal("Warn", scorecard.SummaryStatus);
        Assert.Equal("Warn", scorecard.FamilyScores[0].Status);
        Assert.Equal(80.0, scorecard.FamilyScores[0].ScorePercentage);
    }

    [Fact]
    public void Build_NinetyPercent_ReturnsPass()
    {
        var results = new[]
        {
            PassWithCis("FW-001", "4.1"),
            PassWithCis("FW-002", "4.2"),
            PassWithCis("FW-003", "4.3"),
            PassWithCis("FW-004", "4.4"),
            PassWithCis("FW-005", "4.5"),
            PassWithCis("FW-006", "4.6"),
            PassWithCis("FW-007", "4.7"),
            PassWithCis("FW-008", "4.8"),
            PassWithCis("FW-009", "4.9"),
            FailWithCis("FW-010", "4.10")
        };

        var scorecard = _builder.Build(results);

        Assert.NotNull(scorecard);
        Assert.Equal(90.0, scorecard.OverallScore);
        Assert.Equal("Pass", scorecard.SummaryStatus);
        Assert.Equal("Pass", scorecard.FamilyScores[0].Status);
    }

    [Fact]
    public void Build_MultipleFamilies_GroupsCorrectly()
    {
        var results = new[]
        {
            PassWithCis("FW-001", "3.1"),
            FailWithCis("FW-002", "3.2"),
            PassWithCis("LOG-001", "4.1"),
            PassWithCis("LOG-002", "4.2")
        };

        var scorecard = _builder.Build(results);

        Assert.NotNull(scorecard);
        Assert.Equal(2, scorecard.FamilyScores.Count);

        var netFamily = scorecard.FamilyScores.First(f => f.FamilyId == "3");
        var logFamily = scorecard.FamilyScores.First(f => f.FamilyId == "4");

        Assert.Equal(50.0, netFamily.ScorePercentage);
        Assert.Equal("Fail", netFamily.Status);
        Assert.Equal(100.0, logFamily.ScorePercentage);
        Assert.Equal("Pass", logFamily.Status);
    }

    [Fact]
    public void Build_RuleMapsToMultipleFamilies_CountedInBoth()
    {
        var results = new[]
        {
            new RuleResult
            {
                RuleId = "DUAL-001",
                Category = "Test",
                Passed = true,
                ExplanationKey = "DUAL-001",
                Description = "Dual mapped rule",
                CisMappings = new[]
                {
                    new CisBenchmarkMapping { ControlId = "CIS 3.1", ControlName = "Net", WhyItMatters = "M" },
                    new CisBenchmarkMapping { ControlId = "CIS 4.1", ControlName = "Log", WhyItMatters = "M" }
                }
            }
        };

        var scorecard = _builder.Build(results);

        Assert.NotNull(scorecard);
        Assert.Equal(2, scorecard.FamilyScores.Count);
        Assert.All(scorecard.FamilyScores, f =>
        {
            Assert.Equal(1, f.TotalControls);
            Assert.Equal(1, f.PassedControls);
            Assert.Equal(100.0, f.ScorePercentage);
        });
    }

    [Fact]
    public void Build_MultiFamilyRule_OverallScoreCountsRuleOnce()
    {
        // Rule 1 maps to families 3 and 4, passes
        // Rule 2 maps to family 3 only, fails
        // Family 3: 1 pass / 2 total = 50%
        // Family 4: 1 pass / 1 total = 100%
        // OLD weighted average: (50% * 2 + 100% * 1) / 3 = 66.7% (double-counts Rule 1)
        // NEW rule-level score: 1 pass / 2 rules = 50.0% (each rule counted once)
        var results = new[]
        {
            new RuleResult
            {
                RuleId = "DUAL-001",
                Category = "Test",
                Passed = true,
                ExplanationKey = "DUAL-001",
                Description = "Dual mapped rule",
                CisMappings = new[]
                {
                    new CisBenchmarkMapping { ControlId = "CIS 3.1", ControlName = "Net", WhyItMatters = "M" },
                    new CisBenchmarkMapping { ControlId = "CIS 4.1", ControlName = "Log", WhyItMatters = "M" }
                }
            },
            RuleResult.Fail("FW-002", "Test", "FW-002", "Single mapped", Severity.High, "target", null, new[]
            {
                new CisBenchmarkMapping { ControlId = "CIS 3.2", ControlName = "Net2", WhyItMatters = "M" }
            })
        };

        var scorecard = _builder.Build(results);

        Assert.NotNull(scorecard);
        Assert.Equal(50.0, scorecard.OverallScore); // 1 of 2 rules passed
        Assert.Equal("Fail", scorecard.SummaryStatus);

        var netFamily = scorecard.FamilyScores.First(f => f.FamilyId == "3");
        var logFamily = scorecard.FamilyScores.First(f => f.FamilyId == "4");
        Assert.Equal(50.0, netFamily.ScorePercentage); // 1 of 2 in family 3
        Assert.Equal(100.0, logFamily.ScorePercentage); // 1 of 1 in family 4
    }

    [Fact]
    public void Build_WithHistory_BuildsTrend()
    {
        var history = new InMemoryAuditHistoryStore();
        history.Append(new AuditHistoryEntry
        {
            SnapshotId = "a",
            TimestampUtc = DateTime.UtcNow.AddDays(-2),
            Intent = AgentIntent.FullAudit,
            Scorecard = new ComplianceScorecard
            {
                OverallScore = 60.0,
                SummaryStatus = "Fail",
                FamilyScores = Array.Empty<ControlFamilyScore>()
            }
        });
        history.Append(new AuditHistoryEntry
        {
            SnapshotId = "b",
            TimestampUtc = DateTime.UtcNow.AddDays(-1),
            Intent = AgentIntent.FullAudit,
            Scorecard = new ComplianceScorecard
            {
                OverallScore = 75.0,
                SummaryStatus = "Warn",
                FamilyScores = Array.Empty<ControlFamilyScore>()
            }
        });

        var results = new[] { PassWithCis("FW-001", "4.1") };
        var scorecard = _builder.Build(results, history);

        Assert.NotNull(scorecard);
        Assert.Equal(2, scorecard.Trend.Count);
        Assert.Equal(60.0, scorecard.Trend[0].OverallScore);
        Assert.Equal(75.0, scorecard.Trend[1].OverallScore);
    }

    [Fact]
    public void Build_TrendCappedAtMaxEntries()
    {
        var history = new InMemoryAuditHistoryStore();
        for (int i = 0; i < 15; i++)
        {
            history.Append(new AuditHistoryEntry
            {
                SnapshotId = $"s{i}",
                TimestampUtc = DateTime.UtcNow.AddDays(-15 + i),
                Intent = AgentIntent.FullAudit,
                Scorecard = new ComplianceScorecard
                {
                    OverallScore = i * 1.0,
                    SummaryStatus = "Pass",
                    FamilyScores = Array.Empty<ControlFamilyScore>()
                }
            });
        }

        var results = new[] { PassWithCis("FW-001", "4.1") };
        var scorecard = _builder.Build(results, history);

        Assert.NotNull(scorecard);
        Assert.Equal(10, scorecard.Trend.Count); // capped at MaxTrendPoints
        Assert.Equal(5.0, scorecard.Trend[0].OverallScore); // oldest kept = index 5
        Assert.Equal(14.0, scorecard.Trend[9].OverallScore); // newest = index 14
    }

    [Fact]
    public void Build_NotApplicableRule_DoesNotCountTowardTotal()
    {
        var results = new[]
        {
            PassWithCis("FW-001", "4.1"),
            new RuleResult
            {
                RuleId = "FW-002",
                Category = "Firewall",
                Passed = true,
                Status = RuleStatus.NotApplicable,
                ExplanationKey = "FW-002",
                Description = "Not applicable rule",
                CisMappings = new[]
                {
                    new CisBenchmarkMapping { ControlId = "CIS 4.2", ControlName = "Test", WhyItMatters = "M" }
                }
            }
        };

        var scorecard = _builder.Build(results);

        Assert.NotNull(scorecard);
        Assert.Equal(100.0, scorecard.OverallScore);
        Assert.Single(scorecard.FamilyScores);
        Assert.Equal(1, scorecard.FamilyScores[0].TotalControls);
        Assert.Equal(1, scorecard.FamilyScores[0].PassedControls);
    }

    [Fact]
    public void Build_FullySuppressedRule_ScoreIsOneHundred()
    {
        // A fully suppressed family has no active gaps → 100%
        var results = new[]
        {
            new RuleResult
            {
                RuleId = "FW-001",
                Category = "Firewall",
                Passed = false,
                Status = RuleStatus.Suppressed,
                ExplanationKey = "FW-001",
                Description = "Suppressed rule",
                CisMappings = new[]
                {
                    new CisBenchmarkMapping { ControlId = "CIS 4.1", ControlName = "Test", WhyItMatters = "M" }
                }
            }
        };

        var scorecard = _builder.Build(results);

        Assert.NotNull(scorecard);
        Assert.Equal(100.0, scorecard.OverallScore);
        Assert.Equal(1, scorecard.FamilyScores[0].SuppressedControls);
    }

    [Fact]
    public void Build_SuppressedRulesExcludedFromScore()
    {
        // 2 pass + 1 suppressed + 1 fail = 2/3 applicable = 66.7%
        var results = new[]
        {
            PassWithCis("FW-001", "4.1"),
            PassWithCis("FW-002", "4.2"),
            new RuleResult
            {
                RuleId = "FW-003",
                Category = "Firewall",
                Passed = false,
                Status = RuleStatus.Suppressed,
                ExplanationKey = "FW-003",
                Description = "Suppressed rule",
                CisMappings = new[]
                {
                    new CisBenchmarkMapping { ControlId = "CIS 4.3", ControlName = "Test", WhyItMatters = "M" }
                }
            },
            FailWithCis("FW-004", "4.4")
        };

        var scorecard = _builder.Build(results);

        Assert.NotNull(scorecard);
        Assert.Equal(66.7, scorecard.OverallScore);
        Assert.Equal(4, scorecard.FamilyScores[0].TotalControls);
        Assert.Equal(1, scorecard.FamilyScores[0].SuppressedControls);
    }

    private static RuleResult PassWithCis(string ruleId, string controlSuffix)
    {
        return RuleResult.Pass(ruleId, "Test", ruleId, $"Desc {ruleId}", new[]
        {
            new CisBenchmarkMapping
            {
                ControlId = $"CIS {controlSuffix}",
                ControlName = $"Control {controlSuffix}",
                WhyItMatters = "Test"
            }
        });
    }

    private static RuleResult FailWithCis(string ruleId, string controlSuffix)
    {
        return RuleResult.Fail(ruleId, "Test", ruleId, $"Desc {ruleId}", Severity.High, "target", null, new[]
        {
            new CisBenchmarkMapping
            {
                ControlId = $"CIS {controlSuffix}",
                ControlName = $"Control {controlSuffix}",
                WhyItMatters = "Test"
            }
        });
    }

    private static RuleResult CrashWithCis(string ruleId, string controlSuffix)
    {
        return RuleResult.Crash(ruleId, "Test", $"Desc {ruleId}", new[]
        {
            new CisBenchmarkMapping
            {
                ControlId = $"CIS {controlSuffix}",
                ControlName = $"Control {controlSuffix}",
                WhyItMatters = "Test"
            }
        });
    }
}
