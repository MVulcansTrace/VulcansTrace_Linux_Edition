using System;
using System.Collections.Generic;
using System.Linq;
using VulcansTrace.Linux.Agent.Reports;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// Builds the bounded text shown in the left-panel advisor "Tip" for remediation-plan
/// validation outcomes. Kept pure so the "Tip never grows per finding" guarantee is
/// directly unit-testable without constructing <see cref="MainViewModel"/>.
/// </summary>
public static class AdvisorText
{
    /// <summary>
    /// Maximum number of blocked-section detail lines inlined into a single Agent
    /// transcript message. Beyond this the remainder is summarized with a trailing
    /// count so the chat entry stays readable.
    /// </summary>
    public const int MaxInlineDetailLines = 50;

    /// <summary>
    /// Produces a short, count-based advisor tip plus the per-section detail lines for a
    /// blocked remediation plan. The tip never enumerates rule ids and never repeats the
    /// per-section validator text, so it cannot grow with the number of findings.
    /// </summary>
    /// <param name="result">The validation result from <see cref="RemediationPlanValidator"/>.</param>
    /// <returns>
    /// <c>Tip</c> — a single bounded sentence (empty when the plan is valid or <paramref name="result"/> is null);
    /// <c>DetailLines</c> — the original per-section error messages (empty when valid/null).
    /// </returns>
    public static (string Tip, IReadOnlyList<string> DetailLines) ForBlockedRemediation(ValidationResult? result)
    {
        if (result is null || result.IsValid)
            return (string.Empty, Array.Empty<string>());

        var detail = result.Errors ?? Array.Empty<string>();
        var count = detail.Count;

        var tip = count == 0
            ? "Remediation plan omitted from the evidence bundle because it did not pass safety validation."
            : $"Remediation plan omitted from the evidence bundle: {count} section(s) need rollback guidance before export. See the Agent transcript for details.";

        return (tip, detail);
    }

    /// <summary>
    /// Formats the blocked-section detail for the Agent transcript as a single, bounded
    /// message. Returns <c>null</c> when there is nothing to report.
    /// </summary>
    public static string? FormatBlockedRemediationTranscript(IReadOnlyList<string> detailLines)
    {
        if (detailLines is null || detailLines.Count == 0)
            return null;

        var shown = detailLines.Take(MaxInlineDetailLines);
        var body = string.Join(Environment.NewLine, shown.Select(line => "  • " + line));
        var header = $"Remediation plan omitted from the evidence bundle — {detailLines.Count} section(s) blocked (missing rollback guidance):";
        var suffix = detailLines.Count > MaxInlineDetailLines
            ? $"{Environment.NewLine}  … and {detailLines.Count - MaxInlineDetailLines} more."
            : string.Empty;

        return header + Environment.NewLine + body + suffix;
    }
}
