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
    private readonly Func<AgentIntent, string?, CancellationToken, Task<AgentResult>> _runAudit;

    public AgentFollowUpService(
        AgentAuditState auditState,
        IExplanationProvider explanationProvider,
        IAuditHistoryStore? historyStore,
        ISuppressionStore? suppressionStore,
        Func<AgentIntent, string?, CancellationToken, Task<AgentResult>> runAudit)
    {
        _auditState = auditState ?? throw new ArgumentNullException(nameof(auditState));
        _explanationProvider = explanationProvider ?? throw new ArgumentNullException(nameof(explanationProvider));
        _historyStore = historyStore;
        _suppressionStore = suppressionStore;
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
            AgentIntent.PrioritizeRemediation => HandlePrioritizeRemediationAsync(ct),
            AgentIntent.FixFinding => HandleFixFindingAsync(agentQuery, ct),
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

    private Task<AgentResult> HandlePrioritizeRemediationAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        if (_auditState.LastResult == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.PrioritizeRemediation,
                Summary = "Run an audit first, then ask me what to fix first.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        if (_auditState.LastResult.AgentFindings.Count == 0)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.PrioritizeRemediation,
                Summary = "No active findings to remediate. Great job!",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var builder = new RemediationPlanBuilder(_explanationProvider);
        var plan = builder.Build(_auditState.LastResult.AgentFindings);
        var sorted = plan.Sections.OrderByDescending(s => ParseSeverityFromSummary(s.FindingSummary)).ToList();
        var sortedPlan = plan with { Sections = sorted };

        var parts = new List<string> { "**Remediation Plan — Fix in this order**", "" };
        for (int i = 0; i < sorted.Count; i++)
        {
            var section = sorted[i];
            parts.Add($"{i + 1}. {section.FindingSummary}");
            if (!string.IsNullOrWhiteSpace(section.RiskNote))
            {
                parts.Add($"   Risk: {section.RiskNote}");
            }
            if (section.ApplyCommands.Count > 0)
            {
                parts.Add($"   Action: `{section.ApplyCommands[0].Command}`");
            }
            parts.Add("");
        }

        return Task.FromResult(new AgentResult
        {
            Intent = AgentIntent.PrioritizeRemediation,
            Summary = string.Join("\n", parts),
            AgentFindings = _auditState.LastResult.AgentFindings.OrderByDescending(f => f.Severity).ToList(),
            RemediationPlan = sortedPlan,
            Warnings = Array.Empty<string>()
        });
    }

    private Task<AgentResult> HandleFixFindingAsync(AgentQuery agentQuery, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        if (_auditState.LastResult == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.FixFinding,
                Summary = "Run an audit first, then ask me to fix a specific finding (e.g., \"fix FW-001\").",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var reference = agentQuery.TargetReference;
        if (string.IsNullOrWhiteSpace(reference))
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.FixFinding,
                Summary = "Please specify which finding to fix (e.g., **fix FW-001**).",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var matched = _auditState.FindPreviousFinding(reference);
        if (matched == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.FixFinding,
                Summary = $"I couldn't find finding **{reference}** in the last audit. Run an audit first or check the finding ID.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var builder = new RemediationPlanBuilder(_explanationProvider);
        var plan = builder.Build(new[] { matched });
        var section = plan.Sections.FirstOrDefault();

        if (section == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.FixFinding,
                Summary = $"I found **{reference}** but couldn't build a remediation plan for it.",
                AgentFindings = new[] { matched },
                Warnings = Array.Empty<string>()
            });
        }

        var validation = RemediationPlanValidator.Validate(plan);
        if (!validation.IsValid)
        {
            var parts = new List<string>
            {
                $"**Cannot guide remediation for {reference}**",
                "",
                "This finding has risky or unclassified commands that lack explicit rollback guidance. The plan was blocked for safety.",
                ""
            };
            foreach (var err in validation.Errors)
            {
                parts.Add($"  • {err}");
            }
            parts.Add("");
            parts.Add("Please review the explanation template and ensure rollback commands are provided.");

            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.FixFinding,
                Summary = string.Join("\n", parts),
                AgentFindings = new[] { matched },
                Warnings = validation.Errors.ToList(),
                RemediationPlan = plan
            });
        }

        var summaryParts = new List<string>
        {
            $"**Interactive Remediation: {section.RuleId}**",
            "",
            $"{section.FindingSummary}",
            ""
        };

        if (section.Preconditions.Count > 0)
        {
            summaryParts.Add("**Preconditions:**");
            foreach (var pre in section.Preconditions)
            {
                summaryParts.Add($"  • {pre}");
            }
            summaryParts.Add("");
        }

        if (section.BackupCommands.Count > 0)
        {
            summaryParts.Add($"**Backup ({section.BackupCommands.Count} command(s)):** Run these first to preserve state.");
            summaryParts.Add("");
        }

        summaryParts.Add($"**Apply ({section.ApplyCommands.Count} command(s)):** Step-by-step fix commands.");
        summaryParts.Add("");

        if (section.RollbackCommands.Count > 0 || section.RollbackHints.Count > 0)
        {
            summaryParts.Add($"**Rollback:** Available if something goes wrong.");
            summaryParts.Add("");
        }

        if (section.VerificationCommands.Count > 0)
        {
            summaryParts.Add($"**Verify ({section.VerificationCommands.Count} command(s)):** Confirm the fix worked.");
            summaryParts.Add("");
        }

        summaryParts.Add("Review each command before running it. Use the **Copy** button to grab commands.");

        return Task.FromResult(new AgentResult
        {
            Intent = AgentIntent.FixFinding,
            Summary = string.Join("\n", summaryParts),
            AgentFindings = new[] { matched },
            RemediationPlan = plan,
            Warnings = Array.Empty<string>()
        });
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

    private static Severity ParseSeverityFromSummary(string summary)
    {
        if (summary.Contains("Critical", StringComparison.OrdinalIgnoreCase)) return Severity.Critical;
        if (summary.Contains("High", StringComparison.OrdinalIgnoreCase)) return Severity.High;
        if (summary.Contains("Medium", StringComparison.OrdinalIgnoreCase)) return Severity.Medium;
        if (summary.Contains("Low", StringComparison.OrdinalIgnoreCase)) return Severity.Low;
        return Severity.Info;
    }

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
        _ => AgentIntent.Help
    };
}
