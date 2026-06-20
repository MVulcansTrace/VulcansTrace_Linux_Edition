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
            var previousCycles = existingEntry?.RemediationCycles ?? Array.Empty<RemediationCycle>();
            var cycles = UpdateCyclesOnReturn(previousCycles, existingEntry?.LastRemediationAttemptUtc, existingEntry?.LastVerifiedFixedUtc, result.UtcTimestamp);

            // If the rule is failing and a verified-fix timestamp is present, it is either
            // consumed now (cycle created/closed) or already accounted for in legacy cycle
            // history. Either way, the timestamp should not be carried forward.
            var lastVerifiedFixedUtc = existingEntry?.LastVerifiedFixedUtc;
            if (lastVerifiedFixedUtc.HasValue)
                lastVerifiedFixedUtc = null;

            builder[ruleId] = new RuleMemoryEntry
            {
                RuleId = ruleId,
                Category = representative.Category,
                FirstSeenUtc = existingEntry?.FirstSeenUtc ?? result.UtcTimestamp,
                LastSeenUtc = result.UtcTimestamp,
                SeverityHistory = history,
                LastRemediationAttemptUtc = existingEntry?.LastRemediationAttemptUtc,
                LastVerifiedFixedUtc = lastVerifiedFixedUtc,
                Trend = trend,
                LastSeverity = representative.Severity,
                LastTarget = representative.Target ?? string.Empty,
                RemediationCycles = cycles
            };
        }

        return builder.ToImmutableDictionary(StringComparer.OrdinalIgnoreCase);
    }

    private static IReadOnlyList<RemediationCycle> UpdateCyclesOnReturn(
        IReadOnlyList<RemediationCycle> cycles,
        DateTime? lastRemediationAttemptUtc,
        DateTime? lastVerifiedFixedUtc,
        DateTime returnedUtc)
    {
        if (!lastVerifiedFixedUtc.HasValue)
            return cycles;

        var verified = lastVerifiedFixedUtc.Value;
        var list = cycles.ToList();

        // Close an existing open cycle that matches the last verified-fixed timestamp.
        var openIndex = list.FindIndex(c => !c.IsClosed && c.VerifiedFixedUtc == verified);
        if (openIndex >= 0)
        {
            var existing = list[openIndex];
            list[openIndex] = existing with { ReturnedUtc = returnedUtc };
            return list;
        }

        // Guard against re-creating a cycle for the same verified-fix timestamp.
        if (list.Any(c => c.VerifiedFixedUtc == verified))
            return list;

        // No open cycle exists (e.g., legacy data or verification predated cycle tracking).
        // Create a closed cycle retroactively so wisdom can still be derived.
        var nextNumber = list.Count > 0 ? list.Max(c => c.CycleNumber) + 1 : 1;
        list.Add(new RemediationCycle
        {
            AttemptedUtc = lastRemediationAttemptUtc ?? verified,
            VerifiedFixedUtc = verified,
            ReturnedUtc = returnedUtc,
            CycleNumber = nextNumber
        });

        return list;
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

            var cycles = UpdateCyclesOnVerification(
                entry.RemediationCycles,
                entry.LastRemediationAttemptUtc,
                timestampUtc);

            builder[ruleId] = entry with
            {
                LastVerifiedFixedUtc = timestampUtc,
                LastRemediationAttemptUtc = entry.LastRemediationAttemptUtc ?? timestampUtc,
                RemediationCycles = cycles
            };
        }

        return builder.ToImmutableDictionary(StringComparer.OrdinalIgnoreCase);
    }

    private static IReadOnlyList<RemediationCycle> UpdateCyclesOnVerification(
        IReadOnlyList<RemediationCycle> cycles,
        DateTime? lastRemediationAttemptUtc,
        DateTime verifiedUtc)
    {
        var list = cycles.ToList();

        // If an open cycle already exists, update it rather than creating a duplicate.
        var openIndex = list.FindLastIndex(c => !c.IsClosed);
        if (openIndex >= 0)
        {
            var existing = list[openIndex];

            // Idempotent: same verification timestamp should not mutate the cycle.
            if (existing.VerifiedFixedUtc == verifiedUtc)
                return list;

            // Preserve the original attempt timestamp; only move the verified timestamp forward.
            list[openIndex] = existing with
            {
                AttemptedUtc = existing.AttemptedUtc != default
                    ? existing.AttemptedUtc
                    : (lastRemediationAttemptUtc ?? verifiedUtc),
                VerifiedFixedUtc = verifiedUtc
            };
            return list;
        }

        var nextNumber = list.Count > 0 ? list.Max(c => c.CycleNumber) + 1 : 1;
        list.Add(new RemediationCycle
        {
            AttemptedUtc = lastRemediationAttemptUtc ?? verifiedUtc,
            VerifiedFixedUtc = verifiedUtc,
            CycleNumber = nextNumber
        });

        return list;
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

            var cycles = UpdateCyclesOnAttempt(entry.RemediationCycles, timestampUtc);

            builder[ruleId] = entry with
            {
                LastRemediationAttemptUtc = timestampUtc,
                RemediationCycles = cycles
            };
        }

        return builder.ToImmutableDictionary(StringComparer.OrdinalIgnoreCase);
    }

    private static IReadOnlyList<RemediationCycle> UpdateCyclesOnAttempt(
        IReadOnlyList<RemediationCycle> cycles,
        DateTime attemptedUtc)
    {
        var list = cycles.ToList();

        var openUnverifiedIndex = list.FindLastIndex(c => !c.IsClosed && !c.VerifiedFixedUtc.HasValue);
        if (openUnverifiedIndex >= 0)
        {
            list[openUnverifiedIndex] = list[openUnverifiedIndex] with { AttemptedUtc = attemptedUtc };
            return list;
        }

        var nextNumber = list.Count > 0 ? list.Max(c => c.CycleNumber) + 1 : 1;
        list.Add(new RemediationCycle
        {
            AttemptedUtc = attemptedUtc,
            CycleNumber = nextNumber
        });

        return list;
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
