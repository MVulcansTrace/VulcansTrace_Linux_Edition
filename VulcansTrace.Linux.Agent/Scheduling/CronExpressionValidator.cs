using System.Text.RegularExpressions;

namespace VulcansTrace.Linux.Agent.Scheduling;

/// <summary>
/// Lightweight validator for standard 5-field cron expressions.
/// </summary>
public static partial class CronExpressionValidator
{
    /// <summary>
    /// Returns true if the expression is a syntactically valid 5-field cron string.
    /// </summary>
    public static bool IsValid(string expression)
    {
        if (string.IsNullOrWhiteSpace(expression))
            return false;

        var parts = expression.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 5)
            return false;

        foreach (var part in parts)
        {
            if (!CronFieldRegex().IsMatch(part))
                return false;
        }

        return true;
    }

    [GeneratedRegex(@"^([0-9,*\-/]+)$", RegexOptions.Compiled)]
    private static partial Regex CronFieldRegex();
}
