using System;

namespace VulcansTrace.Linux.Agent.Reports;

/// <summary>
/// Shared human-readable "how long ago" formatting for audit/baseline provenance cues. Extracted so
/// every follow-up reply (short verdict, risk score, baseline view) reports the same age phrasing
/// and a cached answer is never mistaken for a fresh scan.
/// </summary>
public static class AuditAgeFormatter
{
    /// <summary>
    /// Renders a elapsed <see cref="TimeSpan"/> as a compact relative age
    /// ("just now", "12 min ago", "3 hr ago", "2 days ago"). Negative spans (clock skew) clamp to
    /// "just now".
    /// </summary>
    public static string FormatAge(TimeSpan age)
    {
        if (age < TimeSpan.Zero) age = TimeSpan.Zero;
        if (age < TimeSpan.FromMinutes(1)) return "just now";
        if (age < TimeSpan.FromHours(1)) return $"{(int)age.TotalMinutes} min ago";
        if (age < TimeSpan.FromDays(1)) return $"{(int)age.TotalHours} hr ago";
        var days = (int)age.TotalDays;
        return days == 1 ? "1 day ago" : $"{days} days ago";
    }
}
