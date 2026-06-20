using VulcansTrace.Linux.Agent.Dialogue;
using VulcansTrace.Linux.Agent.Memory;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Sessions;
using VulcansTrace.Linux.Agent.Suggestions;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent.Suggestions;

public class AgentSuggestionProviderTests
{
    private readonly AgentSuggestionProvider _provider = new();

    [Fact]
    public void Audit_WithCriticalFinding_ReturnsPrioritizedSuggestions()
    {
        var result = CreateResult(AgentIntent.FullAudit, CreateFinding("FW-001", "Firewall", Severity.Critical));
        var entities = new EntityFrame();

        var suggestions = _provider.GetSuggestions(result, entities);

        Assert.Equal(5, suggestions.Count);
        Assert.Contains(suggestions, s => s.Label == "What should I fix first?");
        Assert.Contains(suggestions, s => s.Label == "Why is this critical?");
        Assert.Contains(suggestions, s => s.Label == "Show only Firewall issues");
        Assert.Contains(suggestions, s => s.Label == "Explain FW-001");
        Assert.Contains(suggestions, s => s.Label == "What's my risk grade?");
    }

    [Fact]
    public void Audit_WithNoFindings_ReturnsBaselineAndExplorationSuggestions()
    {
        var result = CreateResult(AgentIntent.FullAudit);
        var entities = new EntityFrame();

        var suggestions = _provider.GetSuggestions(result, entities);

        Assert.Equal(2, suggestions.Count);
        Assert.Contains(suggestions, s => s.Label == "Set baseline");
        Assert.Contains(suggestions, s => s.Label == "Check another area");
    }

    [Fact]
    public void TargetedAudit_WithNoFindings_SuggestsFullAuditAndBlindSpot()
    {
        var result = CreateResult(AgentIntent.FirewallCheck);
        var entities = new EntityFrame();

        var suggestions = _provider.GetSuggestions(result, entities);

        // Assert the blind-spot chip and the no-findings staples are present without pinning an
        // exact count (brittle against future suggestion additions). The blind-spot chip is the
        // load-bearing assertion.
        Assert.Contains(suggestions, s => s.Label == "Set baseline");
        Assert.Contains(suggestions, s => s.Label == "Check another area");
        Assert.Contains(suggestions, s => s.Label == "Run a full audit");
        Assert.Contains(suggestions, s => s.Query == "check network" && s.Intent == AgentIntent.NetworkCheck);
        Assert.InRange(suggestions.Count, 4, AgentSuggestionProvider.MaxSuggestions);
    }

    [Fact]
    public void ExplainFinding_ReturnsFixAndRelatedSuggestions()
    {
        var result = CreateResult(AgentIntent.ExplainFinding, CreateFinding("SSH-001", "SSH", Severity.High));
        var entities = new EntityFrame { LastRuleId = "SSH-001", LastCategory = "SSH" };

        var suggestions = _provider.GetSuggestions(result, entities);

        Assert.Contains(suggestions, s => s.Label == "Fix it" && s.Query == "fix SSH-001");
        Assert.Contains(suggestions, s => s.Label == "Remediate it" && s.Query == "remediate SSH-001");
        Assert.Contains(suggestions, s => s.Label == "Show related SSH findings");
        Assert.Contains(suggestions, s => s.Label == "What should I fix first?");
    }

    [Fact]
    public void SetBaseline_ReturnsCheckDrift()
    {
        var result = CreateResult(AgentIntent.SetBaseline);

        var suggestions = _provider.GetSuggestions(result, new EntityFrame());

        var suggestion = Assert.Single(suggestions);
        Assert.Equal("Check drift", suggestion.Label);
        Assert.Equal(AgentIntent.CheckDrift, suggestion.Intent);
    }

    [Fact]
    public void CheckDrift_ReturnsBaselineSuggestions()
    {
        var result = CreateResult(AgentIntent.CheckDrift);

        var suggestions = _provider.GetSuggestions(result, new EntityFrame());

        Assert.Equal(2, suggestions.Count);
        Assert.Contains(suggestions, s => s.Label == "Show baseline");
        Assert.Contains(suggestions, s => s.Label == "Update baseline");
    }

    [Fact]
    public void PrioritizeRemediation_ReturnsFixFirstSuggestion()
    {
        var section = new RemediationSection
        {
            RuleId = "FW-001",
            FindingSummary = "[Critical] Firewall is wide open",
            RiskNote = "High exposure"
        };
        var plan = new RemediationPlan { Sections = new[] { section } };
        var result = CreateResult(AgentIntent.PrioritizeRemediation, CreateFinding("FW-001", "Firewall", Severity.Critical)) with
        {
            RemediationPlan = plan
        };
        var entities = new EntityFrame { LastAuditIntent = AgentIntent.FullAudit };

        var suggestions = _provider.GetSuggestions(result, entities);

        Assert.Contains(suggestions, s => s.Label == "Fix FW-001");
        Assert.Contains(suggestions, s => s.Label == "Show all findings");
    }

    [Fact]
    public void Help_ReturnsFullAudit()
    {
        var result = CreateResult(AgentIntent.Help);

        var suggestions = _provider.GetSuggestions(result, new EntityFrame());

        var suggestion = Assert.Single(suggestions);
        Assert.Equal("Run a full audit", suggestion.Label);
    }

    [Fact]
    public void ExplainCritical_ReturnsRiskAndPrioritizationSuggestions()
    {
        var result = CreateResult(AgentIntent.ExplainCritical, CreateFinding("FW-001", "Firewall", Severity.Critical));
        var entities = new EntityFrame { LastAuditIntent = AgentIntent.FullAudit };

        var suggestions = _provider.GetSuggestions(result, entities);

        Assert.Contains(suggestions, s => s.Label == "What should I fix first?");
        Assert.Contains(suggestions, s => s.Label == "What's my risk grade?");
        Assert.Contains(suggestions, s => s.Label == "Show all findings" && s.Intent == AgentIntent.FullAudit);
    }

    [Fact]
    public void UnknownIntent_ReturnsDefaultFullAuditSuggestion()
    {
        // Use a value that is not explicitly handled by the provider.
        var result = CreateResult((AgentIntent)999);

        var suggestions = _provider.GetSuggestions(result, new EntityFrame());

        var suggestion = Assert.Single(suggestions);
        Assert.Equal("Run a full audit", suggestion.Label);
        Assert.Equal(AgentIntent.FullAudit, suggestion.Intent);
    }

    [Fact]
    public void AddSessionNote_ReturnsSessionSuggestions()
    {
        var session = new RemediationSession
        {
            SessionId = "abc12345",
            Status = RemediationSessionStatus.Active,
            RemediationPlan = new RemediationPlan(),
            SourceFindings = Array.Empty<Finding>(),
            StepStates = new Dictionary<string, RemediationStepState>(),
            Timeline = Array.Empty<RemediationSessionEvent>()
        };
        var result = CreateResult(AgentIntent.AddSessionNote) with { RemediationSession = session };

        var suggestions = _provider.GetSuggestions(result, new EntityFrame());

        Assert.Contains(suggestions, s => s.Label == "Verify session" && s.Query == "verify session abc12345");
        Assert.Contains(suggestions, s => s.Label == "List sessions");
        Assert.Contains(suggestions, s => s.Label == "Run a full audit");
    }



    [Fact]
    public void Audit_WithPostureCorrelation_SuggestsFixingPairTogether()
    {
        var finding1 = CreateFinding("FW-002", "Firewall", Severity.High);
        var finding2 = CreateFinding("SSH-002", "SSH", Severity.High);
        var result = CreateResult(AgentIntent.FullAudit, finding1, finding2) with
        {
            PostureCorrelations = new[]
            {
                new PostureCorrelation
                {
                    PatternId = "POSTURE-001",
                    RuleIdA = "FW-002",
                    RuleIdB = "SSH-002",
                    Narrative = "Pair risk.",
                    CombinedSeverity = Severity.Critical,
                    FindingIds = new[] { finding1.Id, finding2.Id }
                }
            }
        };

        var suggestions = _provider.GetSuggestions(result, new EntityFrame());

        Assert.Contains(suggestions, s => s.Label.Contains("FW-002") && s.Label.Contains("SSH-002"));
    }

    [Fact]
    public void Audit_WithStaleFinding_SuggestsPrioritizeBasedOnMemory()
    {
        var result = CreateResult(AgentIntent.FullAudit, CreateFinding("FW-001", "Firewall", Severity.High));
        var entities = new EntityFrame
        {
            RuleHistory = new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase)
            {
                ["FW-001"] = new RuleMemoryEntry
                {
                    RuleId = "FW-001",
                    FirstSeenUtc = DateTime.UtcNow.AddDays(-10),
                    LastSeverity = Severity.High,
                    SeverityHistory = new[]
                    {
                        new RuleSeveritySnapshot { UtcTimestamp = DateTime.UtcNow.AddDays(-10), Severity = Severity.High },
                        new RuleSeveritySnapshot { UtcTimestamp = DateTime.UtcNow, Severity = Severity.High }
                    },
                    Trend = RuleStatusTrend.Stable
                }
            }
        };

        var suggestions = _provider.GetSuggestions(result, entities);

        Assert.Contains(suggestions, s => s.Label.Contains("FW-001") && s.Label.Contains("still open"));
    }

    [Fact]
    public void Audit_WithStaleMemoryForAbsentFinding_DoesNotSuggestMissingRule()
    {
        var result = CreateResult(AgentIntent.FullAudit, CreateFinding("SSH-002", "SSH", Severity.High));
        var entities = new EntityFrame
        {
            RuleHistory = new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase)
            {
                ["FW-001"] = new RuleMemoryEntry
                {
                    RuleId = "FW-001",
                    FirstSeenUtc = DateTime.UtcNow.AddDays(-10),
                    LastSeverity = Severity.High,
                    SeverityHistory = new[]
                    {
                        new RuleSeveritySnapshot { UtcTimestamp = DateTime.UtcNow.AddDays(-10), Severity = Severity.High },
                        new RuleSeveritySnapshot { UtcTimestamp = DateTime.UtcNow.AddDays(-9), Severity = Severity.High }
                    },
                    Trend = RuleStatusTrend.Stable,
                    LastVerifiedFixedUtc = DateTime.UtcNow
                }
            }
        };

        var suggestions = _provider.GetSuggestions(result, entities);

        Assert.DoesNotContain(suggestions, s => s.Label.Contains("FW-001"));
        Assert.DoesNotContain(suggestions, s => s.Query.Contains("FW-001"));
    }

    [Fact]
    public void VerifyRemediation_WithRemainingCorrelatedFinding_SuggestsRelatedFix()
    {
        var finding1 = CreateFinding("FW-002", "Firewall", Severity.High);
        var finding2 = CreateFinding("SSH-002", "SSH", Severity.High);
        var result = CreateResult(AgentIntent.VerifyRemediation, finding1, finding2) with
        {
            PostureCorrelations = new[]
            {
                new PostureCorrelation
                {
                    PatternId = "POSTURE-001",
                    RuleIdA = "FW-002",
                    RuleIdB = "SSH-002",
                    Narrative = "Pair risk.",
                    CombinedSeverity = Severity.Critical,
                    FindingIds = new[] { finding1.Id, finding2.Id }
                }
            }
        };

        var suggestions = _provider.GetSuggestions(result, new EntityFrame());

        Assert.Contains(suggestions, s => s.Label.Contains("Fix related SSH-002"));
    }

    [Fact]
    public void Suggestions_NeverReferenceMissingFinding()
    {
        var result = CreateResult(AgentIntent.FullAudit, CreateFinding("FW-001", "Firewall", Severity.High));
        result = result with
        {
            PostureCorrelations = new[]
            {
                new PostureCorrelation
                {
                    PatternId = "POSTURE-001",
                    RuleIdA = "FW-001",
                    RuleIdB = "MISSING-002",
                    Narrative = "Pair risk.",
                    CombinedSeverity = Severity.Critical,
                    FindingIds = new[] { Guid.NewGuid(), Guid.NewGuid() }
                }
            }
        };

        var suggestions = _provider.GetSuggestions(result, new EntityFrame());

        Assert.DoesNotContain(suggestions, s => s.Label.Contains("MISSING-002"));
    }

    [Fact]
    public void TargetedAudit_WithUncheckedCategories_SuggestsBlindSpotCheck()
    {
        var result = CreateResult(AgentIntent.SshCheck);
        var entities = new EntityFrame
        {
            CheckedCategories = new[]
            {
                new CategoryAuditEntry { Category = "SSH", UtcTimestamp = DateTime.UtcNow }
            }
        };

        var suggestions = _provider.GetSuggestions(result, entities);

        Assert.Contains(suggestions, s => s.Query == "check firewall" && s.Intent == AgentIntent.FirewallCheck);
    }

    [Fact]
    public void FullAudit_WithUncheckedCategories_DoesNotSuggestBlindSpotChecks()
    {
        var result = CreateResult(AgentIntent.FullAudit);
        var entities = new EntityFrame
        {
            CheckedCategories = new[]
            {
                new CategoryAuditEntry { Category = "SSH", UtcTimestamp = DateTime.UtcNow }
            }
        };

        var suggestions = _provider.GetSuggestions(result, entities);

        Assert.DoesNotContain(suggestions, s => s.Query == "check filesystem security");
        Assert.DoesNotContain(suggestions, s => s.Query == "check firewall");
    }

    [Fact]
    public void TargetedAudit_WithAllCategoriesChecked_DoesNotSuggestBlindSpotChecks()
    {
        var result = CreateResult(AgentIntent.SshCheck);
        var entities = new EntityFrame
        {
            CheckedCategories = IntentCategoryMap.AllCategories
                .Select(c => new CategoryAuditEntry { Category = c, UtcTimestamp = DateTime.UtcNow })
                .ToArray()
        };

        var suggestions = _provider.GetSuggestions(result, entities);

        Assert.DoesNotContain(suggestions, s => s.Query == "check filesystem security");
    }

    private static AgentResult CreateResult(AgentIntent intent, params Finding[] findings)
    {
        return new AgentResult
        {
            Intent = intent,
            AgentFindings = findings,
            UtcTimestamp = DateTime.UtcNow
        };
    }

    private static Finding CreateFinding(string ruleId, string category, Severity severity)
    {
        return new Finding
        {
            RuleId = ruleId,
            Category = category,
            Severity = severity,
            ShortDescription = $"{ruleId} issue",
            Details = "Details",
            SourceHost = "localhost",
            Target = "target",
            Confidence = DetectionConfidence.High
        };
    }
}
