namespace VulcansTrace.Linux.Agent.Reports;

/// <summary>
/// Calculates differences between two audit snapshots.
/// </summary>
public static class AuditDiffCalculator
{
    /// <summary>
    /// Calculates the diff between two audit history entries.
    /// </summary>
    /// <param name="before">The older audit entry.</param>
    /// <param name="after">The newer audit entry.</param>
    /// <returns>An <see cref="AuditDiff"/> describing the changes.</returns>
    public static AuditDiff Calculate(AuditHistoryEntry before, AuditHistoryEntry after)
    {
        var beforeDict = before.SnapshotFindings.ToDictionary(f => MakeKey(f.RuleId, f.Target), f => f);
        var afterDict = after.SnapshotFindings.ToDictionary(f => MakeKey(f.RuleId, f.Target), f => f);

        var newFindings = new List<DiffFinding>();
        var resolvedFindings = new List<DiffFinding>();
        var worsenedFindings = new List<SeverityChangeFinding>();
        var improvedFindings = new List<SeverityChangeFinding>();
        var unchangedFindings = new List<DiffFinding>();

        foreach (var (key, afterFinding) in afterDict)
        {
            if (!beforeDict.TryGetValue(key, out var beforeFinding))
            {
                newFindings.Add(ToDiffFinding(afterFinding));
            }
            else
            {
                var beforeSev = ParseSeverity(beforeFinding.Severity);
                var afterSev = ParseSeverity(afterFinding.Severity);

                if (afterSev > beforeSev)
                {
                    worsenedFindings.Add(new SeverityChangeFinding
                    {
                        RuleId = afterFinding.RuleId,
                        Target = afterFinding.Target,
                        OldSeverity = beforeFinding.Severity,
                        NewSeverity = afterFinding.Severity,
                        ShortDescription = afterFinding.ShortDescription
                    });
                }
                else if (afterSev < beforeSev)
                {
                    improvedFindings.Add(new SeverityChangeFinding
                    {
                        RuleId = afterFinding.RuleId,
                        Target = afterFinding.Target,
                        OldSeverity = beforeFinding.Severity,
                        NewSeverity = afterFinding.Severity,
                        ShortDescription = afterFinding.ShortDescription
                    });
                }
                else
                {
                    unchangedFindings.Add(ToDiffFinding(afterFinding));
                }
            }
        }

        foreach (var (key, beforeFinding) in beforeDict)
        {
            if (!afterDict.ContainsKey(key))
            {
                resolvedFindings.Add(ToDiffFinding(beforeFinding));
            }
        }

        return new AuditDiff
        {
            NewFindings = newFindings,
            ResolvedFindings = resolvedFindings,
            WorsenedFindings = worsenedFindings,
            ImprovedFindings = improvedFindings,
            UnchangedFindings = unchangedFindings
        };
    }

    private static string MakeKey(string ruleId, string target) => $"{ruleId}|{target}";

    private static DiffFinding ToDiffFinding(AuditSnapshotFinding f) => new()
    {
        RuleId = f.RuleId,
        Target = f.Target,
        Severity = f.Severity,
        ShortDescription = f.ShortDescription
    };

    private static int ParseSeverity(string severity)
    {
        return severity.ToLowerInvariant() switch
        {
            "info" => 0,
            "low" => 1,
            "medium" => 2,
            "high" => 3,
            "critical" => 4,
            _ => 0
        };
    }
}
