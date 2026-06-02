using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Sessions;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

internal sealed class AgentResultPresenter
{
    private const string AllCategoriesFilter = "All categories";

    private readonly ObservableCollection<AgentMessageViewModel> _messages;
    private readonly ObservableCollection<string> _categoryFilters;
    private readonly Func<SeverityFilterOption?> _getSeverityFilter;
    private readonly Func<string?> _getCategoryFilter;
    private readonly Action<bool> _setPrivilegeWarning;
    private readonly Action<string> _setPrivilegeWarningText;

    public AgentResultPresenter(
        ObservableCollection<AgentMessageViewModel> messages,
        ObservableCollection<string> categoryFilters,
        Func<SeverityFilterOption?> getSeverityFilter,
        Func<string?> getCategoryFilter,
        Action<bool> setPrivilegeWarning,
        Action<string> setPrivilegeWarningText)
    {
        _messages = messages ?? throw new ArgumentNullException(nameof(messages));
        _categoryFilters = categoryFilters ?? throw new ArgumentNullException(nameof(categoryFilters));
        _getSeverityFilter = getSeverityFilter ?? throw new ArgumentNullException(nameof(getSeverityFilter));
        _getCategoryFilter = getCategoryFilter ?? throw new ArgumentNullException(nameof(getCategoryFilter));
        _setPrivilegeWarning = setPrivilegeWarning ?? throw new ArgumentNullException(nameof(setPrivilegeWarning));
        _setPrivilegeWarningText = setPrivilegeWarningText ?? throw new ArgumentNullException(nameof(setPrivilegeWarningText));
    }

    public void PresentFindings(AgentResult result, bool showCapabilityReport = true, bool showPassedCount = true, bool showWarnings = true)
    {
        if (showCapabilityReport && !string.IsNullOrWhiteSpace(result.CapabilityReport))
            AddAgentMessage(result.CapabilityReport, true);

        if (result.Intent == AgentIntent.FixFinding
            && result.Warnings.Count == 0
            && result.RemediationPlan?.Sections.Count == 1)
        {
            AddInteractiveRemediationMessage(result);
        }
        else if (result.Intent == AgentIntent.StartRemediation && result.RemediationSession != null)
        {
            AddSessionMessage(result);
        }
        else if (result.Intent == AgentIntent.ResumeRemediation && result.RemediationSession != null)
        {
            AddSessionMessage(result);
        }
        else if (result.Intent == AgentIntent.VerifyRemediation && result.RemediationSession != null)
        {
            AddVerificationResultMessage(result);
        }
        else if (result.Intent == AgentIntent.ListRemediationSessions)
        {
            AddAgentMessage(result.Summary, result.RemediationSessions.Count == 0);
        }
        else
        {
            AddAgentMessage(result.Summary, result.AgentFindings.Count == 0);

            if (showPassedCount && result.PassedCount > 0)
            {
                AddAgentMessage($"✓ {result.PassedCount} check(s) passed", true);
            }

            if (result.AgentFindings.Count > 0)
            {
                AddAgentFindingGroupSummary(result.AgentFindings);

                _categoryFilters.Clear();
                _categoryFilters.Add(AllCategoriesFilter);
                foreach (var cat in result.AgentFindings.Select(f => f.Category).Distinct().OrderBy(c => c))
                {
                    _categoryFilters.Add(cat);
                }

                var grouped = result.AgentFindings
                    .GroupBy(f => f.Category)
                    .Select(g => new { Category = g.Key, Findings = g.OrderByDescending(f => f.Severity).ToList() })
                    .OrderByDescending(g => g.Findings.Max(f => f.Severity))
                    .ToList();

                foreach (var group in grouped)
                {
                    AddAgentFindingGroup(group.Category, group.Findings);
                }
            }
        }

        if (showWarnings && result.Warnings.Count > 0)
        {
            AddAgentMessage($"Warnings: {string.Join("; ", result.Warnings)}", true);
            DetectPrivilegeWarning(result.Warnings);
        }

        ApplyChatFilters();
    }

    public void AddUserMessage(string text)
    {
        _messages.Add(new AgentMessageViewModel
        {
            Text = text,
            IsUser = true,
            Timestamp = DateTime.Now
        });
    }

    public void AddAgentMessage(string text, bool isInfo)
    {
        _messages.Add(new AgentMessageViewModel
        {
            Text = text,
            IsUser = false,
            IsInfo = isInfo,
            Timestamp = DateTime.Now
        });
    }

    public void AddAgentFinding(Finding finding)
    {
        var ruleIdPrefix = string.IsNullOrEmpty(finding.RuleId) ? "" : $"[{finding.RuleId}] ";
        var verificationCommands = VerificationCommandExtractor.ExtractHowToVerify(finding.Details);

        _messages.Add(new AgentMessageViewModel
        {
            Text = $"{ruleIdPrefix}[{finding.Severity}] {finding.ShortDescription}",
            Details = finding.Details,
            IsUser = false,
            IsInfo = false,
            Severity = finding.Severity,
            Timestamp = DateTime.Now,
            VerificationCommands = verificationCommands
        });
    }

    private void AddAgentFindingGroupSummary(IReadOnlyList<Finding> findings)
    {
        var critical = findings.Count(f => f.Severity == Severity.Critical);
        var high = findings.Count(f => f.Severity == Severity.High);
        var medium = findings.Count(f => f.Severity == Severity.Medium);
        var low = findings.Count(f => f.Severity == Severity.Low);
        var info = findings.Count(f => f.Severity == Severity.Info);

        var parts = new List<string>();
        if (critical > 0) parts.Add($"{critical} Critical");
        if (high > 0) parts.Add($"{high} High");
        if (medium > 0) parts.Add($"{medium} Medium");
        if (low > 0) parts.Add($"{low} Low");
        if (info > 0) parts.Add($"{info} Info");

        var summary = $"Findings: {string.Join(", ", parts)} ({findings.Count} total)";
        _messages.Add(new AgentMessageViewModel
        {
            Text = summary,
            IsUser = false,
            IsInfo = true,
            Timestamp = DateTime.Now
        });
    }

    private void AddAgentFindingGroup(string category, IReadOnlyList<Finding> findings)
    {
        var highCritical = findings.Count(f => f.Severity >= Severity.High);
        var header = highCritical > 0
            ? $"[{category}] {findings.Count} finding(s) — {highCritical} High/Critical"
            : $"[{category}] {findings.Count} finding(s)";

        var details = new StringBuilder();
        foreach (var finding in findings)
        {
            var ruleIdPrefix = string.IsNullOrEmpty(finding.RuleId) ? "" : $"[{finding.RuleId}] ";
            details.AppendLine($"• {ruleIdPrefix}[{finding.Severity}] {finding.ShortDescription}");
        }

        _messages.Add(new AgentMessageViewModel
        {
            Text = header,
            Details = details.ToString().TrimEnd(),
            IsUser = false,
            IsInfo = false,
            Severity = findings.Max(f => f.Severity),
            Timestamp = DateTime.Now,
            Category = category
        });
    }

    private void AddInteractiveRemediationMessage(AgentResult result)
    {
        var section = result.RemediationPlan!.Sections[0];
        var severity = ParseSeverityFromSummary(section.FindingSummary);

        _messages.Add(new AgentMessageViewModel
        {
            Text = result.Summary,
            Details = $"Risk: {section.RiskNote}",
            IsUser = false,
            IsInfo = false,
            Severity = severity,
            Timestamp = DateTime.Now,
            RemediationSection = section
        });
    }

    private void AddSessionMessage(AgentResult result)
    {
        var session = result.RemediationSession!;
        var section = session.RemediationPlan.Sections.FirstOrDefault();
        var severity = section != null ? ParseSeverityFromSummary(section.FindingSummary) : Severity.Info;
        var sectionIsBlocked = section != null
            && session.StepStates.TryGetValue(section.RuleId, out var stepState)
            && stepState == RemediationStepState.Blocked;

        _messages.Add(new AgentMessageViewModel
        {
            Text = result.Summary,
            Details = section != null && !sectionIsBlocked ? $"Risk: {section.RiskNote}" : "",
            IsUser = false,
            IsInfo = false,
            Severity = severity,
            Timestamp = DateTime.Now,
            RemediationSection = sectionIsBlocked ? null : section,
            SessionId = session.SessionId,
            SessionStatus = session.Status,
            SessionTimeline = session.Timeline
        });
    }

    private void AddVerificationResultMessage(AgentResult result)
    {
        var session = result.RemediationSession!;
        var v = session.VerificationResult;

        _messages.Add(new AgentMessageViewModel
        {
            Text = result.Summary,
            IsUser = false,
            IsInfo = false,
            Timestamp = DateTime.Now,
            SessionId = session.SessionId,
            SessionStatus = session.Status,
            IsVerificationResult = true,
            SessionTimeline = session.Timeline
        });
    }

    public void ApplyChatFilters()
    {
        var severityFilter = _getSeverityFilter();
        var categoryFilter = _getCategoryFilter();

        foreach (var msg in _messages)
        {
            if (msg.IsUser || msg.IsInfo || string.IsNullOrEmpty(msg.Category))
            {
                msg.IsVisible = true;
                continue;
            }

            var severityOk = true;
            var categoryOk = true;

            if (severityFilter != null)
            {
                if (severityFilter.MinSeverity == Severity.High && msg.Severity < Severity.High)
                    severityOk = false;
                if (severityFilter.MinSeverity == Severity.Critical && msg.Severity < Severity.Critical)
                    severityOk = false;
            }

            if (!IsAllCategoryFilter(categoryFilter) && !msg.Category.Equals(categoryFilter, StringComparison.OrdinalIgnoreCase))
                categoryOk = false;

            msg.IsVisible = severityOk && categoryOk;
        }
    }

    private void DetectPrivilegeWarning(IReadOnlyList<string> warnings)
    {
        var privilegeWarning = warnings.FirstOrDefault(w =>
            w.Contains("permission", StringComparison.OrdinalIgnoreCase) ||
            w.Contains("privilege", StringComparison.OrdinalIgnoreCase) ||
            w.Contains("denied", StringComparison.OrdinalIgnoreCase) ||
            w.Contains("elevated", StringComparison.OrdinalIgnoreCase));

        if (privilegeWarning != null)
        {
            _setPrivilegeWarning(true);
            _setPrivilegeWarningText("Some inspections are limited without elevated privileges. Process names, connection details, and service states may be hidden. Run with sudo for full visibility.");
        }
    }

    private static Severity ParseSeverityFromSummary(string summary)
    {
        if (summary.Contains("Critical", StringComparison.OrdinalIgnoreCase)) return Severity.Critical;
        if (summary.Contains("High", StringComparison.OrdinalIgnoreCase)) return Severity.High;
        if (summary.Contains("Medium", StringComparison.OrdinalIgnoreCase)) return Severity.Medium;
        if (summary.Contains("Low", StringComparison.OrdinalIgnoreCase)) return Severity.Low;
        return Severity.Info;
    }

    private static bool IsAllCategoryFilter(string? categoryFilter) =>
        string.IsNullOrWhiteSpace(categoryFilter)
            || categoryFilter.Equals(AllCategoriesFilter, StringComparison.OrdinalIgnoreCase);
}
