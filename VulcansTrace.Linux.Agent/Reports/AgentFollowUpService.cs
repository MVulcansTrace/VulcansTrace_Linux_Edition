using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Reports;

internal sealed class AgentFollowUpService
{
    private readonly AgentAuditState _auditState;
    private readonly IExplanationProvider _explanationProvider;
    private readonly IAuditHistoryStore? _historyStore;
    private readonly ISuppressionStore? _suppressionStore;
    private readonly GuidedRemediationService _remediationService;
    private readonly Func<AgentIntent, string?, CancellationToken, Task<AgentResult>> _runAudit;

    public AgentFollowUpService(
        AgentAuditState auditState,
        IExplanationProvider explanationProvider,
        IAuditHistoryStore? historyStore,
        ISuppressionStore? suppressionStore,
        GuidedRemediationService remediationService,
        Func<AgentIntent, string?, CancellationToken, Task<AgentResult>> runAudit)
    {
        _auditState = auditState ?? throw new ArgumentNullException(nameof(auditState));
        _explanationProvider = explanationProvider ?? throw new ArgumentNullException(nameof(explanationProvider));
        _historyStore = historyStore;
        _suppressionStore = suppressionStore;
        _remediationService = remediationService ?? throw new ArgumentNullException(nameof(remediationService));
        _runAudit = runAudit ?? throw new ArgumentNullException(nameof(runAudit));
    }

    public Task<AgentResult> HandleFollowUpAsync(AgentQuery agentQuery, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        return agentQuery.Intent switch
        {
            AgentIntent.ShowChanges => HandleShowChangesAsync(ct),
            AgentIntent.ExplainCritical => HandleExplainCriticalAsync(ct),
            AgentIntent.FilterCategory => HandleFilterCategoryAsync(agentQuery, ct),
            AgentIntent.PrioritizeRemediation => _remediationService.HandlePrioritizeRemediationAsync(ct),
            AgentIntent.FixFinding => _remediationService.HandleFixFindingAsync(agentQuery, ct),
            AgentIntent.ListSuppressed => HandleListSuppressedAsync(ct),
            AgentIntent.RiskScore => HandleRiskScoreAsync(ct),
            _ => Task.FromResult(new AgentResult
            {
                Intent = agentQuery.Intent,
                Summary = "I'm not sure how to answer that. Run an audit first, then try a follow-up question.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            })
        };
    }

    private Task<AgentResult> HandleShowChangesAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        if (_auditState.LastResult == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ShowChanges,
                Summary = "No previous audit to compare against. Run an audit first, then ask what changed.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var allHistory = _historyStore?.GetAll();
        if (allHistory == null || allHistory.Count == 0)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ShowChanges,
                Summary = "No audit history available to compare against. Run at least two audits to see changes.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        AuditHistoryEntry? previous = null;
        for (int i = 0; i < allHistory.Count; i++)
        {
            if (allHistory[i].TimestampUtc != _auditState.LastResult.UtcTimestamp)
            {
                previous = allHistory[i];
                break;
            }
        }

        if (previous == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ShowChanges,
                Summary = "No previous audit found to compare against. Run at least two audits to see changes.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var currentEntry = new AuditHistoryEntry
        {
            SnapshotId = Guid.NewGuid().ToString("N")[..8],
            TimestampUtc = _auditState.LastResult.UtcTimestamp,
            Intent = _auditState.LastResult.Intent,
            TotalFindings = _auditState.LastResult.AgentFindings.Count,
            SnapshotFindings = _auditState.LastResult.AgentFindings.Select(ToSnapshotFinding).ToList()
        };

        var diff = AuditDiffCalculator.Calculate(previous, currentEntry);

        var actionableFindings = new List<Finding>();
        foreach (var df in diff.NewFindings.Concat(diff.WorsenedFindings.Select(w => new DiffFinding
        {
            RuleId = w.RuleId,
            Target = w.Target,
            Severity = w.NewSeverity,
            ShortDescription = w.ShortDescription,
            Fingerprint = w.Fingerprint
        })))
        {
            actionableFindings.Add(new Finding
            {
                RuleId = df.RuleId,
                Category = "Change",
                Severity = ParseSeverityString(df.Severity),
                SourceHost = "localhost",
                Target = df.Target,
                ShortDescription = df.ShortDescription,
                Details = $"This finding is new or worsened since the last audit.",
                TimeRangeStart = DateTime.UtcNow,
                TimeRangeEnd = DateTime.UtcNow
            });
        }

        return Task.FromResult(new AgentResult
        {
            Intent = AgentIntent.ShowChanges,
            Summary = diff.Narrative,
            AgentFindings = actionableFindings,
            AuditDiff = diff,
            Warnings = Array.Empty<string>()
        });
    }

    private Task<AgentResult> HandleExplainCriticalAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        if (_auditState.LastResult == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ExplainCritical,
                Summary = "Run an audit first, then ask me why findings are critical.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var criticalHigh = _auditState.LastResult.AgentFindings.Where(f => f.Severity >= Severity.High).ToList();

        if (criticalHigh.Count == 0)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ExplainCritical,
                Summary = "No Critical or High findings in the last audit. Everything is at Medium or below.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var parts = new List<string> { $"**Critical / High Findings ({criticalHigh.Count})**", "" };
        foreach (var finding in criticalHigh)
        {
            var structured = _explanationProvider.ParseStructuredFromText(finding.Details);
            parts.Add($"**[{finding.RuleId}] {finding.ShortDescription}**");
            parts.Add(string.IsNullOrEmpty(structured.WhyItMatters) ? finding.Details : structured.WhyItMatters);
            parts.Add("");
        }

        return Task.FromResult(new AgentResult
        {
            Intent = AgentIntent.ExplainCritical,
            Summary = string.Join("\n", parts),
            AgentFindings = criticalHigh,
            Warnings = Array.Empty<string>()
        });
    }

    private async Task<AgentResult> HandleFilterCategoryAsync(AgentQuery agentQuery, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        var category = agentQuery.TargetReference;

        if (_auditState.LastResult == null)
        {
            var fallbackIntent = InferIntentFromCategory(category);
            if (fallbackIntent != AgentIntent.Help)
            {
                var savedLastResult = _auditState.LastResult;
                try
                {
                    var fallbackResult = await _runAudit(fallbackIntent, null, ct);
                    return fallbackResult with { Intent = AgentIntent.FilterCategory };
                }
                finally
                {
                    _auditState.RememberResult(savedLastResult);
                }
            }

            return new AgentResult
            {
                Intent = AgentIntent.FilterCategory,
                Summary = "Run an audit first, then ask me to filter by category.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            };
        }

        if (string.IsNullOrWhiteSpace(category))
        {
            return new AgentResult
            {
                Intent = AgentIntent.FilterCategory,
                Summary = "Please specify a category to filter by (e.g., 'show only firewall issues').",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            };
        }

        var filtered = _auditState.LastResult.AgentFindings
            .Where(f => f.Category.Contains(category, StringComparison.OrdinalIgnoreCase))
            .ToList();

        var summary = filtered.Count > 0
            ? $"Showing {filtered.Count} {category} issue(s) from the last audit."
            : $"No {category} issues found in the last audit.";

        return new AgentResult
        {
            Intent = AgentIntent.FilterCategory,
            Summary = summary,
            AgentFindings = filtered,
            Warnings = Array.Empty<string>()
        };
    }

    private Task<AgentResult> HandleListSuppressedAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        if (_auditState.LastResult == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ListSuppressed,
                Summary = "Run an audit first, then ask me which findings are suppressed.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var suppressed = _auditState.LastResult.RuleResults.Where(r => r.Status == RuleStatus.Suppressed).ToList();

        if (suppressed.Count == 0)
        {
            var extra = _suppressionStore != null
                ? $" ({_suppressionStore.GetAll().Count} active suppression(s) in store, but none matched the last audit.)"
                : "";
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ListSuppressed,
                Summary = $"No findings were suppressed in the last audit.{extra}",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var parts = new List<string> { $"**Suppressed Findings ({suppressed.Count})**", "" };
        foreach (var result in suppressed)
        {
            parts.Add($"• [{result.RuleId}] {result.Description} — Target: {result.Target}");
        }

        if (_suppressionStore != null)
        {
            parts.Add($"\nTotal active suppressions in store: {_suppressionStore.GetAll().Count}");
        }

        return Task.FromResult(new AgentResult
        {
            Intent = AgentIntent.ListSuppressed,
            Summary = string.Join("\n", parts),
            AgentFindings = Array.Empty<Finding>(),
            Warnings = Array.Empty<string>()
        });
    }

    private Task<AgentResult> HandleRiskScoreAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        if (_auditState.LastResult == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.RiskScore,
                Summary = "Run an audit first, then ask for your risk score.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var risk = _auditState.LastResult.RiskScorecard;
        if (risk == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.RiskScore,
                Summary = "No risk scorecard available for the last audit.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var summary = $"**Risk Grade: {risk.LetterGrade}** ({risk.NumericScore:F1}) — {risk.SummaryStatus}\n" +
            $"Risk-relevant findings: {risk.TotalFindings}";

        if (risk.ByCategory.Count > 0)
        {
            summary += "\n\n**Top categories by deduction:**";
            foreach (var cat in risk.ByCategory.Take(5))
            {
                summary += $"\n• {cat.Category}: {cat.FindingCount} finding(s), avg severity {cat.AverageSeverity:F1}, deduction {cat.TotalDeduction:F1}";
            }
        }

        return Task.FromResult(new AgentResult
        {
            Intent = AgentIntent.RiskScore,
            Summary = summary,
            AgentFindings = _auditState.LastResult.AgentFindings,
            Warnings = _auditState.LastResult.Warnings,
            RiskScorecard = risk
        });
    }

    private static AuditSnapshotFinding ToSnapshotFinding(Finding f) => new()
    {
        RuleId = f.RuleId ?? $"__null-{f.Fingerprint ?? f.Id.ToString("N")}",
        Target = f.Target,
        Severity = f.Severity.ToString(),
        ShortDescription = f.ShortDescription,
        Category = f.Category,
        Fingerprint = f.Fingerprint
    };

    private static Severity ParseSeverityString(string severity) => severity.ToLowerInvariant() switch
    {
        "info" => Severity.Info,
        "low" => Severity.Low,
        "medium" => Severity.Medium,
        "high" => Severity.High,
        "critical" => Severity.Critical,
        _ => Severity.Info
    };

    private static AgentIntent InferIntentFromCategory(string? category) => category?.ToLowerInvariant() switch
    {
        "firewall" or "iptables" or "nftables" => AgentIntent.FirewallCheck,
        "network" => AgentIntent.NetworkCheck,
        "service" or "daemon" => AgentIntent.ServiceCheck,
        "port" => AgentIntent.PortCheck,
        "ssh" or "sshd" => AgentIntent.SshCheck,
        "file" or "filepermission" or "permissions" => AgentIntent.FilePermissionCheck,
        "filesystem" or "suid" or "sgid" or "world-writable" or "sticky" or "unowned" => AgentIntent.FilesystemAuditCheck,
        "kernel" => AgentIntent.KernelCheck,
        "user" or "useraccount" or "account" or "password" or "shadow" or "uid" or "pam" => AgentIntent.UserAccountCheck,
        "logging" or "rsyslog" or "journald" or "audit" or "auditd" or "logrotate" or "forwarding" or "syslog" => AgentIntent.LoggingAuditCheck,
        "cron" or "crontab" or "scheduled" => AgentIntent.CronJobCheck,
        "packagevulnerability" or "package" or "cve" => AgentIntent.PackageVulnerabilityCheck,
        "container" or "docker" => AgentIntent.ContainerCheck,
        "kubernetes" or "k8s" or "pod" => AgentIntent.KubernetesCheck,
        "threatintel" or "threat-intel" or "ioc" => AgentIntent.ThreatIntelCheck,
        "yara" or "malware" => AgentIntent.YaraCheck,
        _ => AgentIntent.Help
    };
}
