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
        else if ((result.Intent == AgentIntent.AddSessionNote || result.Intent == AgentIntent.AddStepNote)
            && result.RemediationSession != null)
        {
            AddNoteConfirmationMessage(result);
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
        var groupBadge = FormatGroupBadge(finding);
        var details = FormatFindingDetails(finding);

        _messages.Add(new AgentMessageViewModel
        {
            Text = $"{ruleIdPrefix}[{finding.Severity}] {finding.ShortDescription}{groupBadge}",
            Details = details,
            IsUser = false,
            IsInfo = false,
            Severity = finding.Severity,
            Confidence = finding.Confidence.ToString(),
            EvidenceSignalsDisplay = FormatEvidenceSignals(finding.EvidenceSignals),
            Timestamp = DateTime.Now,
            VerificationCommands = verificationCommands
        });
    }

    private void AddAgentFindingGroupSummary(IReadOnlyList<Finding> findings)
    {
        var critical = findings.Where(f => f.Severity == Severity.Critical).Sum(GetRawFindingCount);
        var high = findings.Where(f => f.Severity == Severity.High).Sum(GetRawFindingCount);
        var medium = findings.Where(f => f.Severity == Severity.Medium).Sum(GetRawFindingCount);
        var low = findings.Where(f => f.Severity == Severity.Low).Sum(GetRawFindingCount);
        var info = findings.Where(f => f.Severity == Severity.Info).Sum(GetRawFindingCount);

        var parts = new List<string>();
        if (critical > 0) parts.Add($"{critical} Critical");
        if (high > 0) parts.Add($"{high} High");
        if (medium > 0) parts.Add($"{medium} Medium");
        if (low > 0) parts.Add($"{low} Low");
        if (info > 0) parts.Add($"{info} Info");

        var rawTotal = findings.Sum(GetRawFindingCount);
        var totalLabel = rawTotal == findings.Count
            ? $"{findings.Count} total"
            : $"{findings.Count} representative group(s), {rawTotal} raw findings";
        var summary = $"Findings: {string.Join(", ", parts)} ({totalLabel})";
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
        var rawTotal = findings.Sum(GetRawFindingCount);
        var highCritical = findings.Where(f => f.Severity >= Severity.High).Sum(GetRawFindingCount);
        var countLabel = rawTotal == findings.Count
            ? $"{findings.Count} finding(s)"
            : $"{findings.Count} representative group(s), {rawTotal} raw finding(s)";
        var header = highCritical > 0
            ? $"[{category}] {countLabel} — {highCritical} High/Critical"
            : $"[{category}] {countLabel}";

        var details = new StringBuilder();
        foreach (var finding in findings)
        {
            var ruleIdPrefix = string.IsNullOrEmpty(finding.RuleId) ? "" : $"[{finding.RuleId}] ";
            var confidence = finding.Confidence == DetectionConfidence.Unknown
                ? string.Empty
                : $" confidence {finding.Confidence}";
            var signals = FormatEvidenceSignals(finding.EvidenceSignals);
            var signalText = string.IsNullOrEmpty(signals) ? string.Empty : $" ({signals})";
            details.AppendLine($"• {ruleIdPrefix}[{finding.Severity}{confidence}] {finding.ShortDescription}{FormatGroupBadge(finding)}{signalText}");
        }

        _messages.Add(new AgentMessageViewModel
        {
            Text = header,
            Details = details.ToString().TrimEnd(),
            IsUser = false,
            IsInfo = false,
            Severity = findings.Max(f => f.Severity),
            Confidence = findings.Select(f => f.Confidence).OrderByDescending(c => c).FirstOrDefault().ToString(),
            EvidenceSignalsDisplay = FormatEvidenceSignals(findings.SelectMany(f => f.EvidenceSignals).DistinctBy(s => s.Name).ToList()),
            Timestamp = DateTime.Now,
            Category = category
        });
    }

    private static string FormatGroupBadge(Finding finding) =>
        finding.GroupedCount > 1 ? $" x{finding.GroupedCount}" : string.Empty;

    private static int GetRawFindingCount(Finding finding) => Math.Max(1, finding.GroupedCount);

    private static string FormatFindingDetails(Finding finding)
    {
        if (finding.GroupedCount <= 1 &&
            finding.RepresentativeTargets.Count == 0 &&
            finding.RiskDrivers.Count == 0)
        {
            return finding.Details;
        }

        var details = new StringBuilder(finding.Details.TrimEnd());
        if (details.Length > 0)
        {
            details.AppendLine();
            details.AppendLine();
        }

        if (finding.GroupedCount > 1)
        {
            details.AppendLine($"Grouped findings: {finding.GroupedCount}");
        }

        if (finding.RepresentativeTargets.Count > 0)
        {
            details.AppendLine($"Representative targets: {string.Join("; ", finding.RepresentativeTargets)}");
        }

        if (finding.RiskDrivers.Count > 0)
        {
            details.AppendLine($"Risk drivers: {string.Join("; ", finding.RiskDrivers)}");
        }

        return details.ToString().TrimEnd();
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

    private void AddNoteConfirmationMessage(AgentResult result)
    {
        var session = result.RemediationSession!;
        var note = session.Notes.LastOrDefault();
        if (note == null)
        {
            AddAgentMessage(result.Summary, true);
            return;
        }

        var location = string.IsNullOrEmpty(note.RuleId)
            ? $"session {session.SessionId}"
            : $"step {note.RuleId} in session {session.SessionId}";
        var evidenceHint = note.EvidenceLinks.Count > 0
            ? $" ({note.EvidenceLinks.Count} evidence link(s))"
            : "";

        _messages.Add(new AgentMessageViewModel
        {
            Text = $"Note added to {location}{evidenceHint}: {note.Text}",
            IsUser = false,
            IsInfo = true,
            Timestamp = DateTime.Now,
            SessionId = session.SessionId,
            SessionStatus = session.Status,
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

    private static string FormatEvidenceSignals(IReadOnlyList<EvidenceSignal> signals)
    {
        if (signals.Count == 0)
            return string.Empty;

        return string.Join(", ", signals.Select(s => s.Name));
    }

    private static bool IsAllCategoryFilter(string? categoryFilter) =>
        string.IsNullOrWhiteSpace(categoryFilter)
            || categoryFilter.Equals(AllCategoriesFilter, StringComparison.OrdinalIgnoreCase);
}
