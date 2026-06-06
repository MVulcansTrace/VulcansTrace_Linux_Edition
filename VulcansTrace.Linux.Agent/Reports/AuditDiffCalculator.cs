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
        var beforeFindings = before.SnapshotFindings.ToList();
        var matchedBefore = new bool[beforeFindings.Count];

        var newFindings = new List<DiffFinding>();
        var resolvedFindings = new List<DiffFinding>();
        var worsenedFindings = new List<SeverityChangeFinding>();
        var improvedFindings = new List<SeverityChangeFinding>();
        var confidenceChangedFindings = new List<ConfidenceChangeFinding>();
        var unchangedFindings = new List<DiffFinding>();

        foreach (var afterFinding in after.SnapshotFindings)
        {
            var beforeIndex = FindMatchingBefore(beforeFindings, matchedBefore, afterFinding);
            if (beforeIndex < 0)
            {
                newFindings.Add(ToDiffFinding(afterFinding));
            }
            else
            {
                matchedBefore[beforeIndex] = true;
                var beforeFinding = beforeFindings[beforeIndex];
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
                        OldConfidence = beforeFinding.Confidence,
                        NewConfidence = afterFinding.Confidence,
                        EvidenceSignals = afterFinding.EvidenceSignals,
                        ShortDescription = afterFinding.ShortDescription,
                        GroupedCount = afterFinding.GroupedCount,
                        RepresentativeTargets = afterFinding.RepresentativeTargets,
                        RiskDrivers = afterFinding.RiskDrivers,
                        Fingerprint = afterFinding.Fingerprint ?? beforeFinding.Fingerprint
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
                        OldConfidence = beforeFinding.Confidence,
                        NewConfidence = afterFinding.Confidence,
                        EvidenceSignals = afterFinding.EvidenceSignals,
                        ShortDescription = afterFinding.ShortDescription,
                        GroupedCount = afterFinding.GroupedCount,
                        RepresentativeTargets = afterFinding.RepresentativeTargets,
                        RiskDrivers = afterFinding.RiskDrivers,
                        Fingerprint = afterFinding.Fingerprint ?? beforeFinding.Fingerprint
                    });
                }
                else if (HasMeaningfulConfidenceChange(beforeFinding.Confidence, afterFinding.Confidence))
                {
                    confidenceChangedFindings.Add(new ConfidenceChangeFinding
                    {
                        RuleId = afterFinding.RuleId,
                        Target = afterFinding.Target,
                        Severity = afterFinding.Severity,
                        OldConfidence = beforeFinding.Confidence,
                        NewConfidence = afterFinding.Confidence,
                        EvidenceSignals = afterFinding.EvidenceSignals,
                        ShortDescription = afterFinding.ShortDescription,
                        GroupedCount = afterFinding.GroupedCount,
                        RepresentativeTargets = afterFinding.RepresentativeTargets,
                        RiskDrivers = afterFinding.RiskDrivers,
                        Fingerprint = afterFinding.Fingerprint ?? beforeFinding.Fingerprint
                    });
                }
                else
                {
                    unchangedFindings.Add(ToDiffFinding(afterFinding));
                }
            }
        }

        for (var i = 0; i < beforeFindings.Count; i++)
        {
            if (!matchedBefore[i])
            {
                resolvedFindings.Add(ToDiffFinding(beforeFindings[i]));
            }
        }

        return new AuditDiff
        {
            NewFindings = newFindings,
            ResolvedFindings = resolvedFindings,
            WorsenedFindings = worsenedFindings,
            ImprovedFindings = improvedFindings,
            ConfidenceChangedFindings = confidenceChangedFindings,
            UnchangedFindings = unchangedFindings
        };
    }

    private static int FindMatchingBefore(
        IReadOnlyList<AuditSnapshotFinding> beforeFindings,
        IReadOnlyList<bool> matchedBefore,
        AuditSnapshotFinding afterFinding)
    {
        if (!string.IsNullOrEmpty(afterFinding.Fingerprint))
        {
            for (var i = 0; i < beforeFindings.Count; i++)
            {
                if (!matchedBefore[i] &&
                    !string.IsNullOrEmpty(beforeFindings[i].Fingerprint) &&
                    string.Equals(beforeFindings[i].Fingerprint, afterFinding.Fingerprint, StringComparison.OrdinalIgnoreCase))
                {
                    return i;
                }
            }
        }

        for (var i = 0; i < beforeFindings.Count; i++)
        {
            if (matchedBefore[i])
                continue;

            var beforeFinding = beforeFindings[i];
            if (!string.IsNullOrEmpty(beforeFinding.Fingerprint) &&
                !string.IsNullOrEmpty(afterFinding.Fingerprint))
            {
                continue;
            }

            if (IsSameLegacyFinding(beforeFinding, afterFinding))
                return i;
        }

        return -1;
    }

    private static bool IsSameLegacyFinding(AuditSnapshotFinding beforeFinding, AuditSnapshotFinding afterFinding)
    {
        return string.Equals(beforeFinding.RuleId, afterFinding.RuleId, StringComparison.OrdinalIgnoreCase)
            && string.Equals(beforeFinding.Target, afterFinding.Target, StringComparison.OrdinalIgnoreCase);
    }

    private static bool HasMeaningfulConfidenceChange(string beforeConfidence, string afterConfidence)
    {
        if (string.Equals(beforeConfidence, afterConfidence, StringComparison.OrdinalIgnoreCase))
            return false;

        return !IsUnknownConfidence(beforeConfidence) && !IsUnknownConfidence(afterConfidence);
    }

    private static bool IsUnknownConfidence(string confidence) =>
        string.IsNullOrWhiteSpace(confidence)
        || confidence.Equals("Unknown", StringComparison.OrdinalIgnoreCase);

    private static DiffFinding ToDiffFinding(AuditSnapshotFinding f) => new()
    {
        RuleId = f.RuleId,
        Target = f.Target,
        Severity = f.Severity,
        Confidence = f.Confidence,
        EvidenceSignals = f.EvidenceSignals,
        ShortDescription = f.ShortDescription,
        GroupedCount = f.GroupedCount,
        RepresentativeTargets = f.RepresentativeTargets,
        RiskDrivers = f.RiskDrivers,
        Fingerprint = f.Fingerprint
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
