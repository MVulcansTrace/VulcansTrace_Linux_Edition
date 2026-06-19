using System.Collections.Immutable;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Memory;

/// <summary>
/// Default implementation of <see cref="IRuleMemoryRecorder"/>.
/// Maintains per-rule severity history and derives a trend from the most recent change.
/// </summary>
public sealed class RuleMemoryRecorder : IRuleMemoryRecorder
{
    /// <summary>
    /// Maximum age of a severity snapshot before it is pruned from history.
    /// </summary>
    public static readonly TimeSpan DefaultMaxSnapshotAge = TimeSpan.FromDays(90);

    /// <summary>
    /// Maximum number of severity snapshots to retain per rule.
    /// </summary>
    public const int MaxSnapshotsPerRule = 100;

    private readonly TimeSpan _maxSnapshotAge;

    /// <summary>
    /// Initializes a new <see cref="RuleMemoryRecorder"/> with the default retention policy.
    /// </summary>
    public RuleMemoryRecorder()
        : this(DefaultMaxSnapshotAge)
    {
    }

    /// <summary>
    /// Initializes a new <see cref="RuleMemoryRecorder"/> with a custom retention policy.
    /// </summary>
    /// <param name="maxSnapshotAge">The maximum age of retained severity snapshots.</param>
    public RuleMemoryRecorder(TimeSpan maxSnapshotAge)
    {
        _maxSnapshotAge = maxSnapshotAge;
    }

    /// <inheritdoc />
    public IReadOnlyDictionary<string, RuleMemoryEntry> Record(AgentResult result, IReadOnlyDictionary<string, RuleMemoryEntry> existing)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(existing);

        var cutoff = result.UtcTimestamp - _maxSnapshotAge;
        var builder = new Dictionary<string, RuleMemoryEntry>(existing, StringComparer.OrdinalIgnoreCase);

        // Group findings by RuleId so multiple findings sharing a rule produce exactly one
        // snapshot per audit. Use the highest severity and the first matching target.
        var groupedByRule = result.AgentFindings
            .Where(f => !string.IsNullOrWhiteSpace(f.RuleId))
            .GroupBy(f => f.RuleId!, StringComparer.OrdinalIgnoreCase);

        foreach (var group in groupedByRule)
        {
            var ruleId = group.Key;
            var representative = group.OrderByDescending(f => f.Severity).First();
            var existingEntry = builder.TryGetValue(ruleId, out var entry) ? entry : null;

            var history = existingEntry?.SeverityHistory ?? Array.Empty<RuleSeveritySnapshot>();
            history = history
                .Where(s => s.UtcTimestamp >= cutoff)
                .OrderBy(s => s.UtcTimestamp)
                .TakeLast(MaxSnapshotsPerRule - 1)
                .ToList();

            var newSnapshot = new RuleSeveritySnapshot
            {
                UtcTimestamp = result.UtcTimestamp,
                Severity = representative.Severity,
                Target = representative.Target ?? string.Empty
            };

            history = history.Append(newSnapshot).ToList();

            var trend = ComputeTrend(history);

            builder[ruleId] = new RuleMemoryEntry
            {
                RuleId = ruleId,
                Category = representative.Category,
                FirstSeenUtc = existingEntry?.FirstSeenUtc ?? result.UtcTimestamp,
                LastSeenUtc = result.UtcTimestamp,
                SeverityHistory = history,
                LastRemediationAttemptUtc = existingEntry?.LastRemediationAttemptUtc,
                LastVerifiedFixedUtc = existingEntry?.LastVerifiedFixedUtc,
                Trend = trend,
                LastSeverity = representative.Severity,
                LastTarget = representative.Target ?? string.Empty
            };
        }

        return builder.ToImmutableDictionary(StringComparer.OrdinalIgnoreCase);
    }

    /// <inheritdoc />
    public IReadOnlyDictionary<string, RuleMemoryEntry> MarkVerifiedFixed(
        IEnumerable<string> ruleIds,
        DateTime timestampUtc,
        IReadOnlyDictionary<string, RuleMemoryEntry> existing)
    {
        ArgumentNullException.ThrowIfNull(ruleIds);
        ArgumentNullException.ThrowIfNull(existing);

        var builder = new Dictionary<string, RuleMemoryEntry>(existing, StringComparer.OrdinalIgnoreCase);

        foreach (var ruleId in ruleIds.Where(r => !string.IsNullOrWhiteSpace(r)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!builder.TryGetValue(ruleId, out var entry))
                continue;

            builder[ruleId] = entry with
            {
                LastVerifiedFixedUtc = timestampUtc,
                LastRemediationAttemptUtc = entry.LastRemediationAttemptUtc ?? timestampUtc
            };
        }

        return builder.ToImmutableDictionary(StringComparer.OrdinalIgnoreCase);
    }

    /// <inheritdoc />
    public IReadOnlyDictionary<string, RuleMemoryEntry> MarkRemediationAttempt(
        IEnumerable<string> ruleIds,
        DateTime timestampUtc,
        IReadOnlyDictionary<string, RuleMemoryEntry> existing)
    {
        ArgumentNullException.ThrowIfNull(ruleIds);
        ArgumentNullException.ThrowIfNull(existing);

        var builder = new Dictionary<string, RuleMemoryEntry>(existing, StringComparer.OrdinalIgnoreCase);

        foreach (var ruleId in ruleIds.Where(r => !string.IsNullOrWhiteSpace(r)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!builder.TryGetValue(ruleId, out var entry))
                continue;

            builder[ruleId] = entry with
            {
                LastRemediationAttemptUtc = timestampUtc
            };
        }

        return builder.ToImmutableDictionary(StringComparer.OrdinalIgnoreCase);
    }

    private static RuleStatusTrend ComputeTrend(IReadOnlyList<RuleSeveritySnapshot> history)
    {
        if (history.Count < 2)
            return RuleStatusTrend.New;

        var previous = history[^2].Severity;
        var current = history[^1].Severity;

        if (current > previous)
            return RuleStatusTrend.Worsening;

        if (current < previous)
            return RuleStatusTrend.Improving;

        return RuleStatusTrend.Stable;
    }
}
