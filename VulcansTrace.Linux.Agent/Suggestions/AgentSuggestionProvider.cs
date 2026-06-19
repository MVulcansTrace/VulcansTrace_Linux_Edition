using VulcansTrace.Linux.Agent.Dialogue;
using VulcansTrace.Linux.Agent.Memory;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Sessions;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Suggestions;

/// <summary>
/// Generates deterministic, context-aware follow-up suggestions based on the
/// current agent result and conversation entity frame.
/// </summary>
internal sealed class AgentSuggestionProvider : IAgentSuggestionProvider
{
    /// <summary>Maximum number of suggestions returned for a single result.</summary>
    internal const int MaxSuggestions = 5;

    /// <inheritdoc />
    public IReadOnlyList<SuggestedFollowUp> GetSuggestions(AgentResult result, EntityFrame entities)
    {
        var suggestions = new List<SuggestedFollowUp>();

        switch (result.Intent)
        {
            case AgentIntent.FullAudit:
            case AgentIntent.FirewallCheck:
            case AgentIntent.NetworkCheck:
            case AgentIntent.ServiceCheck:
            case AgentIntent.PortCheck:
            case AgentIntent.SshCheck:
            case AgentIntent.FilePermissionCheck:
            case AgentIntent.FilesystemAuditCheck:
            case AgentIntent.KernelCheck:
            case AgentIntent.UserAccountCheck:
            case AgentIntent.LoggingAuditCheck:
            case AgentIntent.CronJobCheck:
            case AgentIntent.PackageVulnerabilityCheck:
            case AgentIntent.ContainerCheck:
            case AgentIntent.KubernetesCheck:
            case AgentIntent.ThreatIntelCheck:
            case AgentIntent.YaraCheck:
            case AgentIntent.ProcessRuntimeCheck:
                AddAuditSuggestions(result, entities, suggestions);
                break;

            case AgentIntent.ExplainFinding:
                AddExplanationSuggestions(result, entities, suggestions);
                break;

            case AgentIntent.FixFinding:
            case AgentIntent.StartRemediation:
            case AgentIntent.ResumeRemediation:
                AddActiveRemediationSuggestions(result, entities, suggestions);
                break;

            case AgentIntent.VerifyRemediation:
                AddPostVerificationSuggestions(result, entities, suggestions);
                break;

            case AgentIntent.PrioritizeRemediation:
                AddPrioritizationSuggestions(result, entities, suggestions);
                break;

            case AgentIntent.RiskScore:
                AddRiskScoreSuggestions(result, entities, suggestions);
                break;

            case AgentIntent.FilterCategory:
                AddFilterCategorySuggestions(result, entities, suggestions);
                break;

            case AgentIntent.ShowChanges:
                AddShowChangesSuggestions(result, entities, suggestions);
                break;

            case AgentIntent.SetBaseline:
                Add(new SuggestedFollowUp { Label = "Check drift", Query = "check drift", Intent = AgentIntent.CheckDrift }, suggestions);
                break;

            case AgentIntent.CheckDrift:
                Add(new SuggestedFollowUp { Label = "Show baseline", Query = "show baseline", Intent = AgentIntent.ShowBaseline }, suggestions);
                Add(new SuggestedFollowUp { Label = "Update baseline", Query = "set baseline", Intent = AgentIntent.SetBaseline }, suggestions);
                break;

            case AgentIntent.ShowBaseline:
                Add(new SuggestedFollowUp { Label = "Check drift", Query = "check drift", Intent = AgentIntent.CheckDrift }, suggestions);
                Add(new SuggestedFollowUp { Label = "Run a full audit", Query = "run a full audit", Intent = AgentIntent.FullAudit }, suggestions);
                break;

            case AgentIntent.ListSuppressed:
                Add(new SuggestedFollowUp { Label = "Run a full audit", Query = "run a full audit", Intent = AgentIntent.FullAudit }, suggestions);
                Add(new SuggestedFollowUp { Label = "Show changes", Query = "what changed", Intent = AgentIntent.ShowChanges }, suggestions);
                break;

            case AgentIntent.ExplainCritical:
                AddExplainCriticalSuggestions(result, entities, suggestions);
                break;

            case AgentIntent.AddSessionNote:
            case AgentIntent.AddStepNote:
                AddNoteSuggestions(result, entities, suggestions);
                break;

            case AgentIntent.ListRemediationSessions:
                AddSessionListSuggestions(result, entities, suggestions);
                break;

            case AgentIntent.Help:
                Add(new SuggestedFollowUp { Label = "Run a full audit", Query = "run a full audit", Intent = AgentIntent.FullAudit }, suggestions);
                break;

            default:
                Add(new SuggestedFollowUp { Label = "Run a full audit", Query = "run a full audit", Intent = AgentIntent.FullAudit }, suggestions);
                break;
        }

        return suggestions.Take(MaxSuggestions).ToList();
    }

    private static void AddAuditSuggestions(AgentResult result, EntityFrame entities, List<SuggestedFollowUp> suggestions)
    {
        if (result.AgentFindings.Count == 0)
        {
            Add(new SuggestedFollowUp { Label = "Set baseline", Query = "set baseline", Intent = AgentIntent.SetBaseline }, suggestions);
            Add(new SuggestedFollowUp { Label = "Check another area", Query = "what can you check?", Intent = AgentIntent.Help }, suggestions);
            if (result.Intent != AgentIntent.FullAudit)
            {
                Add(new SuggestedFollowUp { Label = "Run a full audit", Query = "run a full audit", Intent = AgentIntent.FullAudit }, suggestions);
            }
            return;
        }

        var topFinding = GetTopFinding(result.AgentFindings);
        var topCategory = GetTopCategory(result.AgentFindings);
        var hasHighCritical = result.AgentFindings.Any(f => f.Severity >= Severity.High);

        Add(new SuggestedFollowUp { Label = "What should I fix first?", Query = "what should i fix first?", Intent = AgentIntent.PrioritizeRemediation }, suggestions);

        if (hasHighCritical)
        {
            Add(new SuggestedFollowUp { Label = "Why is this critical?", Query = "why is this critical?", Intent = AgentIntent.ExplainCritical }, suggestions);
        }

        AddPostureCorrelationSuggestions(result, entities, suggestions);
        AddMemoryAwareSuggestions(result, entities, suggestions);

        if (!string.IsNullOrWhiteSpace(topCategory))
        {
            Add(new SuggestedFollowUp
            {
                Label = $"Show only {topCategory} issues",
                Query = $"show only {topCategory} issues",
                Intent = AgentIntent.FilterCategory
            }, suggestions);
        }

        if (!string.IsNullOrWhiteSpace(topFinding?.RuleId))
        {
            Add(new SuggestedFollowUp
            {
                Label = $"Explain {topFinding.RuleId}",
                Query = $"explain {topFinding.RuleId}",
                Intent = AgentIntent.ExplainFinding
            }, suggestions);
        }

        Add(new SuggestedFollowUp { Label = "What's my risk grade?", Query = "what's my risk grade?", Intent = AgentIntent.RiskScore }, suggestions);
        Add(new SuggestedFollowUp { Label = "Set baseline", Query = "set baseline", Intent = AgentIntent.SetBaseline }, suggestions);
    }

    private static void AddPostureCorrelationSuggestions(AgentResult result, EntityFrame entities, List<SuggestedFollowUp> suggestions)
    {
        var correlation = result.PostureCorrelations.FirstOrDefault();
        if (correlation == null)
            return;

        var hasA = result.AgentFindings.Any(f => !string.IsNullOrWhiteSpace(f.RuleId)
            && f.RuleId.Equals(correlation.RuleIdA, StringComparison.OrdinalIgnoreCase));
        var hasB = result.AgentFindings.Any(f => !string.IsNullOrWhiteSpace(f.RuleId)
            && f.RuleId.Equals(correlation.RuleIdB, StringComparison.OrdinalIgnoreCase));

        if (!hasA || !hasB)
            return;

        Add(new SuggestedFollowUp
        {
            Label = $"Fix {correlation.RuleIdA} and {correlation.RuleIdB} together",
            Query = $"remediate {correlation.RuleIdA} {correlation.RuleIdB}",
            Intent = AgentIntent.StartRemediation
        }, suggestions);
    }

    private static void AddMemoryAwareSuggestions(AgentResult result, EntityFrame entities, List<SuggestedFollowUp> suggestions)
    {
        var currentRuleIds = result.AgentFindings
            .Select(f => f.RuleId)
            .Where(r => !string.IsNullOrWhiteSpace(r))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var stale = entities.RuleHistory.Values
            .Where(e => currentRuleIds.Contains(e.RuleId))
            .Where(e => e.SeverityHistory.Count >= 2)
            .Where(e => (DateTime.UtcNow - e.FirstSeenUtc).TotalDays >= 7)
            .OrderByDescending(e => e.LastSeverity)
            .FirstOrDefault();

        if (stale == null)
            return;

        var trendText = stale.Trend switch
        {
            RuleStatusTrend.Worsening => "is worsening",
            RuleStatusTrend.Stable => "is still open",
            RuleStatusTrend.Improving => "is improving",
            _ => "has history"
        };

        Add(new SuggestedFollowUp
        {
            Label = $"Prioritize {stale.RuleId} — {trendText}",
            Query = $"fix {stale.RuleId}",
            Intent = AgentIntent.FixFinding
        }, suggestions);
    }

    private static void AddExplanationSuggestions(AgentResult result, EntityFrame entities, List<SuggestedFollowUp> suggestions)
    {
        var ruleId = entities.LastRuleId;
        var category = entities.LastCategory;

        if (!string.IsNullOrWhiteSpace(ruleId))
        {
            Add(new SuggestedFollowUp { Label = "Fix it", Query = $"fix {ruleId}", Intent = AgentIntent.FixFinding }, suggestions);
            Add(new SuggestedFollowUp { Label = "Remediate it", Query = $"remediate {ruleId}", Intent = AgentIntent.StartRemediation }, suggestions);
        }

        if (!string.IsNullOrWhiteSpace(category))
        {
            Add(new SuggestedFollowUp
            {
                Label = $"Show related {category} findings",
                Query = $"show only {category} issues",
                Intent = AgentIntent.FilterCategory
            }, suggestions);
        }

        Add(new SuggestedFollowUp { Label = "What should I fix first?", Query = "what should I fix first?", Intent = AgentIntent.PrioritizeRemediation }, suggestions);

        if (result.AgentFindings.Count > 1)
        {
            Add(new SuggestedFollowUp { Label = "Show all findings", Query = "show all findings", Intent = entities.LastAuditIntent }, suggestions);
        }
    }

    private static void AddActiveRemediationSuggestions(AgentResult result, EntityFrame entities, List<SuggestedFollowUp> suggestions)
    {
        var sessionId = result.RemediationSession?.SessionId ?? entities.LastRemediationSessionId;

        if (!string.IsNullOrWhiteSpace(sessionId))
        {
            Add(new SuggestedFollowUp { Label = "Verify session", Query = $"verify session {sessionId}", Intent = AgentIntent.VerifyRemediation }, suggestions);
            Add(new SuggestedFollowUp { Label = "Add a note", Query = $"add note to session {sessionId}", Intent = AgentIntent.AddSessionNote }, suggestions);
        }

        Add(new SuggestedFollowUp { Label = "List sessions", Query = "list sessions", Intent = AgentIntent.ListRemediationSessions }, suggestions);
    }

    private static void AddPostVerificationSuggestions(AgentResult result, EntityFrame entities, List<SuggestedFollowUp> suggestions)
    {
        var sessionId = result.RemediationSession?.SessionId ?? entities.LastRemediationSessionId;

        if (!string.IsNullOrWhiteSpace(sessionId))
        {
            Add(new SuggestedFollowUp { Label = "Add a note", Query = $"add note to session {sessionId}", Intent = AgentIntent.AddSessionNote }, suggestions);
        }

        // If a correlated finding remains after verification, suggest addressing it next.
        var correlation = result.PostureCorrelations.FirstOrDefault();
        if (correlation != null)
        {
            var ruleAFound = result.AgentFindings.Any(f => !string.IsNullOrWhiteSpace(f.RuleId)
                && f.RuleId.Equals(correlation.RuleIdA, StringComparison.OrdinalIgnoreCase));
            var remainingRuleId = ruleAFound ? correlation.RuleIdB : correlation.RuleIdA;

            if (result.AgentFindings.Any(f => !string.IsNullOrWhiteSpace(f.RuleId)
                && f.RuleId.Equals(remainingRuleId, StringComparison.OrdinalIgnoreCase)))
            {
                Add(new SuggestedFollowUp
                {
                    Label = $"Fix related {remainingRuleId}",
                    Query = $"fix {remainingRuleId}",
                    Intent = AgentIntent.FixFinding
                }, suggestions);
            }
        }

        Add(new SuggestedFollowUp { Label = "List sessions", Query = "list sessions", Intent = AgentIntent.ListRemediationSessions }, suggestions);
        Add(new SuggestedFollowUp { Label = "Run a full audit", Query = "run a full audit", Intent = AgentIntent.FullAudit }, suggestions);
    }

    private static void AddPrioritizationSuggestions(AgentResult result, EntityFrame entities, List<SuggestedFollowUp> suggestions)
    {
        var firstRuleId = result.RemediationPlan?.Sections.FirstOrDefault()?.RuleId;

        if (!string.IsNullOrWhiteSpace(firstRuleId))
        {
            Add(new SuggestedFollowUp { Label = $"Fix {firstRuleId}", Query = $"fix {firstRuleId}", Intent = AgentIntent.FixFinding }, suggestions);
        }

        Add(new SuggestedFollowUp { Label = "Show all findings", Query = "show all findings", Intent = entities.LastAuditIntent }, suggestions);
        Add(new SuggestedFollowUp { Label = "What's my risk grade?", Query = "what's my risk grade?", Intent = AgentIntent.RiskScore }, suggestions);
    }

    private static void AddRiskScoreSuggestions(AgentResult result, EntityFrame entities, List<SuggestedFollowUp> suggestions)
    {
        var topCategory = result.RiskScorecard?.ByCategory
            .OrderByDescending(c => c.TotalDeduction)
            .FirstOrDefault()?.Category;

        if (!string.IsNullOrWhiteSpace(topCategory))
        {
            Add(new SuggestedFollowUp
            {
                Label = $"Show only {topCategory} issues",
                Query = $"show only {topCategory} issues",
                Intent = AgentIntent.FilterCategory
            }, suggestions);
        }

        Add(new SuggestedFollowUp { Label = "What should I fix first?", Query = "what should I fix first?", Intent = AgentIntent.PrioritizeRemediation }, suggestions);
        Add(new SuggestedFollowUp { Label = "Show changes", Query = "what changed", Intent = AgentIntent.ShowChanges }, suggestions);
    }

    private static void AddFilterCategorySuggestions(AgentResult result, EntityFrame entities, List<SuggestedFollowUp> suggestions)
    {
        var topFinding = GetTopFinding(result.AgentFindings);

        if (!string.IsNullOrWhiteSpace(topFinding?.RuleId))
        {
            Add(new SuggestedFollowUp { Label = $"Explain {topFinding.RuleId}", Query = $"explain {topFinding.RuleId}", Intent = AgentIntent.ExplainFinding }, suggestions);
            Add(new SuggestedFollowUp { Label = $"Fix {topFinding.RuleId}", Query = $"fix {topFinding.RuleId}", Intent = AgentIntent.FixFinding }, suggestions);
        }

        if (entities.LastAuditIntent != AgentIntent.Help)
        {
            Add(new SuggestedFollowUp { Label = "Show all findings", Query = "show all findings", Intent = entities.LastAuditIntent }, suggestions);
        }

        Add(new SuggestedFollowUp { Label = "What's my risk grade?", Query = "what's my risk grade?", Intent = AgentIntent.RiskScore }, suggestions);
    }

    private static void AddShowChangesSuggestions(AgentResult result, EntityFrame entities, List<SuggestedFollowUp> suggestions)
    {
        Add(new SuggestedFollowUp { Label = "What should I fix first?", Query = "what should I fix first?", Intent = AgentIntent.PrioritizeRemediation }, suggestions);
        Add(new SuggestedFollowUp { Label = "Set baseline", Query = "set baseline", Intent = AgentIntent.SetBaseline }, suggestions);

        if (entities.LastAuditIntent != AgentIntent.Help)
        {
            Add(new SuggestedFollowUp { Label = "Show all findings", Query = "show all findings", Intent = entities.LastAuditIntent }, suggestions);
        }
    }

    private static void AddSessionListSuggestions(AgentResult result, EntityFrame entities, List<SuggestedFollowUp> suggestions)
    {
        var firstSession = result.RemediationSessions.FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(firstSession?.SessionId))
        {
            Add(new SuggestedFollowUp
            {
                Label = $"Resume session {firstSession.SessionId}",
                Query = $"resume session {firstSession.SessionId}",
                Intent = AgentIntent.ResumeRemediation
            }, suggestions);
        }

        Add(new SuggestedFollowUp { Label = "Run a full audit", Query = "run a full audit", Intent = AgentIntent.FullAudit }, suggestions);
    }

    private static void AddExplainCriticalSuggestions(AgentResult result, EntityFrame entities, List<SuggestedFollowUp> suggestions)
    {
        Add(new SuggestedFollowUp { Label = "What should I fix first?", Query = "what should I fix first?", Intent = AgentIntent.PrioritizeRemediation }, suggestions);
        Add(new SuggestedFollowUp { Label = "What's my risk grade?", Query = "what's my risk grade?", Intent = AgentIntent.RiskScore }, suggestions);
        Add(new SuggestedFollowUp { Label = "Show all findings", Query = "show all findings", Intent = entities.LastAuditIntent }, suggestions);
    }

    private static void AddNoteSuggestions(AgentResult result, EntityFrame entities, List<SuggestedFollowUp> suggestions)
    {
        var sessionId = result.RemediationSession?.SessionId ?? entities.LastRemediationSessionId;

        if (!string.IsNullOrWhiteSpace(sessionId)
            && result.RemediationSession?.Status == RemediationSessionStatus.Active)
        {
            Add(new SuggestedFollowUp { Label = "Verify session", Query = $"verify session {sessionId}", Intent = AgentIntent.VerifyRemediation }, suggestions);
        }

        Add(new SuggestedFollowUp { Label = "List sessions", Query = "list sessions", Intent = AgentIntent.ListRemediationSessions }, suggestions);
        Add(new SuggestedFollowUp { Label = "Run a full audit", Query = "run a full audit", Intent = AgentIntent.FullAudit }, suggestions);
    }

    private static void Add(SuggestedFollowUp suggestion, List<SuggestedFollowUp> suggestions)
    {
        if (suggestions.Any(s =>
            s.Label.Equals(suggestion.Label, StringComparison.OrdinalIgnoreCase)
            && s.Query.Equals(suggestion.Query, StringComparison.OrdinalIgnoreCase)))
        {
            return;
        }

        suggestions.Add(suggestion);
    }

    private static Finding? GetTopFinding(IReadOnlyList<Finding> findings)
    {
        if (findings.Count == 0)
            return null;

        return findings
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.RuleId, StringComparer.OrdinalIgnoreCase)
            .First();
    }

    private static string? GetTopCategory(IReadOnlyList<Finding> findings)
    {
        if (findings.Count == 0)
            return null;

        return findings
            .GroupBy(f => f.Category)
            .OrderByDescending(g => g.Max(f => f.Severity))
            .ThenByDescending(g => g.Count())
            .ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.Key)
            .FirstOrDefault();
    }
}
