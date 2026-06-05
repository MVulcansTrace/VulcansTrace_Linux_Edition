using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Engine.LogDiff;

/// <summary>
/// Compares two <see cref="AnalysisResult"/> instances and produces a <see cref="LogDiffResult"/>
/// describing Added, Removed, Changed, and Unchanged connection patterns and findings.
/// </summary>
public sealed class LogDiffAnalyzer
{
    /// <summary>
    /// Compares a baseline analysis against an incident analysis.
    /// </summary>
    /// <param name="baseline">The older or reference analysis result.</param>
    /// <param name="incident">The newer or comparison analysis result.</param>
    /// <returns>A <see cref="LogDiffResult"/> containing the diff.</returns>
    public LogDiffResult Compare(AnalysisResult baseline, AnalysisResult incident)
    {
        ArgumentNullException.ThrowIfNull(baseline);
        ArgumentNullException.ThrowIfNull(incident);

        var baselinePatterns = GroupEvents(baseline.Entries);
        var incidentPatterns = GroupEvents(incident.Entries);

        var diffEvents = new List<DiffEvent>();
        var matchedBaselineKeys = new HashSet<string>();

        foreach (var kvp in incidentPatterns)
        {
            var key = kvp.Key;
            var incidentPattern = kvp.Value;

            if (baselinePatterns.TryGetValue(key, out var baselinePattern))
            {
                matchedBaselineKeys.Add(key);
                var state = ClassifyEventChange(baselinePattern, incidentPattern);
                diffEvents.Add(BuildDiffEvent(key, state, baselinePattern, incidentPattern));
            }
            else
            {
                diffEvents.Add(BuildDiffEvent(key, LogDiffState.Added, null, incidentPattern));
            }
        }

        foreach (var kvp in baselinePatterns)
        {
            if (!matchedBaselineKeys.Contains(kvp.Key))
            {
                diffEvents.Add(BuildDiffEvent(kvp.Key, LogDiffState.Removed, kvp.Value, null));
            }
        }

        var diffFindings = DiffFindings(baseline.Findings, incident.Findings);

        return new LogDiffResult
        {
            Events = diffEvents.OrderByDescending(e => e.State == LogDiffState.Added)
                               .ThenByDescending(e => e.State == LogDiffState.Changed)
                               .ThenByDescending(e => e.State == LogDiffState.Removed)
                               .ThenBy(e => e.ConnectionKey)
                               .ToList(),
            Findings = diffFindings,
            BaselineTimeRangeStart = baseline.TimeRangeStart,
            BaselineTimeRangeEnd = baseline.TimeRangeEnd,
            IncidentTimeRangeStart = incident.TimeRangeStart,
            IncidentTimeRangeEnd = incident.TimeRangeEnd
        };
    }

    private static Dictionary<string, ConnectionPattern> GroupEvents(IReadOnlyList<UnifiedEvent> entries)
    {
        var groups = new Dictionary<string, List<UnifiedEvent>>();

        foreach (var entry in entries)
        {
            var key = GetTrafficPatternKey(entry);
            if (!groups.TryGetValue(key, out var list))
            {
                list = new List<UnifiedEvent>();
                groups[key] = list;
            }
            list.Add(entry);
        }

        return groups.ToDictionary(
            g => g.Key,
            g => new ConnectionPattern(g.Value));
    }

    private static string GetTrafficPatternKey(UnifiedEvent entry)
        => $"{entry.SourceIP}:*-{entry.DestinationIP}:{entry.DestinationPort}-{entry.Protocol}";

    private static LogDiffState ClassifyEventChange(ConnectionPattern baseline, ConnectionPattern incident)
    {
        // Count delta threshold: > 20% change relative to baseline
        double ratio = baseline.Count > 0
            ? Math.Abs(incident.Count - baseline.Count) / (double)baseline.Count
            : (incident.Count > 0 ? 1.0 : 0.0);

        if (ratio > 0.20)
        {
            return LogDiffState.Changed;
        }

        // Action distribution change
        var baselineDominant = GetDominantAction(baseline.ActionCounts);
        var incidentDominant = GetDominantAction(incident.ActionCounts);

        if (!string.Equals(baselineDominant, incidentDominant, StringComparison.OrdinalIgnoreCase))
        {
            return LogDiffState.Changed;
        }

        // If action sets differ (e.g., one side has ACCEPT+DROP, other has only ACCEPT)
        var baselineKeys = new HashSet<string>(baseline.ActionCounts.Keys, StringComparer.OrdinalIgnoreCase);
        var incidentKeys = new HashSet<string>(incident.ActionCounts.Keys, StringComparer.OrdinalIgnoreCase);

        if (!baselineKeys.SetEquals(incidentKeys))
        {
            return LogDiffState.Changed;
        }

        return LogDiffState.Unchanged;
    }

    private static string GetDominantAction(IReadOnlyDictionary<string, int> actionCounts)
    {
        if (actionCounts.Count == 0) return "UNKNOWN";
        return actionCounts.OrderByDescending(kvp => kvp.Value).First().Key;
    }

    private static DiffEvent BuildDiffEvent(
        string connectionKey,
        LogDiffState state,
        ConnectionPattern? baseline,
        ConnectionPattern? incident)
    {
        var rep = incident?.Representative ?? baseline?.Representative;

        return new DiffEvent
        {
            ConnectionKey = connectionKey,
            State = state,
            BaselineCount = baseline?.Count ?? 0,
            IncidentCount = incident?.Count ?? 0,
            SourceIP = rep?.SourceIP ?? string.Empty,
            DestinationIP = rep?.DestinationIP ?? string.Empty,
            SourcePort = rep?.SourcePort ?? 0,
            DestinationPort = rep?.DestinationPort ?? 0,
            Protocol = rep?.Protocol ?? string.Empty,
            BaselineFirstSeen = baseline?.FirstSeen ?? DateTime.MinValue,
            BaselineLastSeen = baseline?.LastSeen ?? DateTime.MinValue,
            IncidentFirstSeen = incident?.FirstSeen ?? DateTime.MinValue,
            IncidentLastSeen = incident?.LastSeen ?? DateTime.MinValue,
            BaselineActions = baseline?.ActionCounts ?? new Dictionary<string, int>(),
            IncidentActions = incident?.ActionCounts ?? new Dictionary<string, int>()
        };
    }

    private static IReadOnlyList<DiffFinding> DiffFindings(
        IReadOnlyList<Finding> baselineFindings,
        IReadOnlyList<Finding> incidentFindings)
    {
        var baselineByFingerprint = baselineFindings
            .GroupBy(f => f.Fingerprint, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

        var incidentByFingerprint = incidentFindings
            .GroupBy(f => f.Fingerprint, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

        var result = new List<DiffFinding>();
        var matchedBaseline = new HashSet<string>();

        foreach (var kvp in incidentByFingerprint)
        {
            var fingerprint = kvp.Key;
            var incidentFinding = kvp.Value;

            if (baselineByFingerprint.TryGetValue(fingerprint, out var baselineFinding))
            {
                matchedBaseline.Add(fingerprint);

                if (baselineFinding.Severity != incidentFinding.Severity)
                {
                    result.Add(new DiffFinding
                    {
                        Finding = incidentFinding,
                        State = LogDiffState.Changed,
                        OldSeverity = baselineFinding.Severity,
                        NewSeverity = incidentFinding.Severity
                    });
                }
                else
                {
                    result.Add(new DiffFinding
                    {
                        Finding = incidentFinding,
                        State = LogDiffState.Unchanged
                    });
                }
            }
            else
            {
                result.Add(new DiffFinding
                {
                    Finding = incidentFinding,
                    State = LogDiffState.Added
                });
            }
        }

        foreach (var kvp in baselineByFingerprint)
        {
            if (!matchedBaseline.Contains(kvp.Key))
            {
                result.Add(new DiffFinding
                {
                    Finding = kvp.Value,
                    State = LogDiffState.Removed
                });
            }
        }

        return result.OrderByDescending(f => f.State == LogDiffState.Added)
                     .ThenByDescending(f => f.State == LogDiffState.Changed)
                     .ThenByDescending(f => f.State == LogDiffState.Removed)
                     .ThenBy(f => f.Finding.Category)
                     .ThenBy(f => f.Finding.Fingerprint)
                     .ToList();
    }

    private sealed class ConnectionPattern
    {
        public int Count { get; }
        public UnifiedEvent Representative { get; }
        public DateTime FirstSeen { get; }
        public DateTime LastSeen { get; }
        public Dictionary<string, int> ActionCounts { get; }

        public ConnectionPattern(IReadOnlyList<UnifiedEvent> events)
        {
            Count = events.Count;
            Representative = events[0];

            FirstSeen = events.Min(e => e.Timestamp);
            LastSeen = events.Max(e => e.Timestamp);

            ActionCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (var e in events)
            {
                var action = string.IsNullOrWhiteSpace(e.Action) ? "UNKNOWN" : e.Action;
                ActionCounts[action] = ActionCounts.GetValueOrDefault(action) + 1;
            }
        }
    }
}
