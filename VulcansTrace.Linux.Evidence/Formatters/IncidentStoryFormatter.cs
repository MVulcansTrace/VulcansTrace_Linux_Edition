using System.Globalization;
using System.Text;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Evidence.Formatters;

/// <summary>
/// Generates a flowing attack narrative (incident story) from a Trace Map result.
/// </summary>
public sealed class IncidentStoryFormatter
{
    /// <summary>
    /// Produces a structured <see cref="IncidentStoryResult"/> from findings and correlations.
    /// </summary>
    public IncidentStoryResult Format(TraceMapResult traceMap)
    {
        var findings = traceMap.Findings;
        var edges = traceMap.Edges;

        if (findings.Count == 0)
        {
            return new IncidentStoryResult
            {
                Beats = Array.Empty<StoryBeat>(),
                LikelyChain = "No findings.",
                HasCriticalChain = false,
                Recommendations = Array.Empty<string>(),
                Markdown = "No findings to narrate."
            };
        }

        var findingById = findings.DistinctBy(f => f.Id).ToDictionary(f => f.Id);
        // Only log-event findings carry real clock times; agent rule findings are scan-time
        // snapshots and must not influence the date-format decision for event labels.
        var useDateInTimestamp = findings
            .Where(f => HasTimestamp(f) && string.IsNullOrEmpty(f.RuleId))
            .Select(f => f.TimeRangeStart.Date)
            .Distinct()
            .Take(2)
            .Count() > 1;

        var orderedFindings = findings
            .Select((finding, index) => new { Finding = finding, Index = index })
            .OrderBy(item => HasTimestamp(item.Finding) ? 0 : 1)
            .ThenBy(item => HasTimestamp(item.Finding) ? item.Finding.TimeRangeStart : DateTime.MaxValue)
            .ThenBy(item => item.Index)
            .Select(item => item.Finding)
            .ToList();

        // Build one beat per finding, then collapse beats that share a timestamp label
        // and category (e.g. three Service findings from the same scan minute) into a
        // single beat with a finding count, so the story does not repeat identical lines.
        var accumulators = new List<BeatAccumulator>();
        var indexByKey = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var f in orderedFindings)
        {
            var verb = VerbForCategory(f.Category);
            var narrativeName = NarrativeNameForCategory(f.Category);

            // Agent rule findings (RuleId set) are point-in-time config snapshots: their timestamp
            // is the scan time, not an event time, so rendering [HH:mm] would imply something
            // happened at that moment. The per-category collapse then groups all snapshots of a
            // category under one beat.
            // Assumption: "RuleId set" == "configuration snapshot". This holds for rule and
            // log-detector findings today (no engine detector sets RuleId), but synthesized
            // findings that DO carry a RuleId — e.g. remediation countermeasures or proactive
            // alerts — are events and would be misclassified if they ever flow into a trace map.
            var isSnapshot = !string.IsNullOrEmpty(f.RuleId);
            var timestampLabel = isSnapshot ? SnapshotTimestampLabel : FormatTimestampLabel(f.TimeRangeStart, useDateInTimestamp);
            var key = $"{timestampLabel}|{f.Category}";

            if (indexByKey.TryGetValue(key, out var existingIndex))
            {
                var existing = accumulators[existingIndex];
                existing.Count++;
                if (f.Severity > existing.Beat.Severity)
                {
                    existing.Beat = existing.Beat with { Severity = f.Severity };
                }
                continue;
            }

            indexByKey[key] = accumulators.Count;
            accumulators.Add(new BeatAccumulator
            {
                Beat = new StoryBeat
                {
                    Timestamp = f.TimeRangeStart,
                    HasTimestamp = HasTimestamp(f),
                    TimestampLabel = timestampLabel,
                    Narrative = string.Empty, // set below, once the group count is known
                    Category = f.Category,
                    Severity = f.Severity,
                    Kind = isSnapshot ? StoryBeatKind.Snapshot : StoryBeatKind.Event
                },
                Sentence = $"{narrativeName} {verb}"
            });
        }

        var beats = accumulators
            .Select(a => a.Beat with
            {
                Narrative = a.Count > 1 ? $"{a.Sentence} ({a.Count} findings)." : $"{a.Sentence}."
            })
            .ToList();

        string likelyChain;
        bool hasCriticalChain = false;
        if (traceMap.CriticalChains.Count > 0)
        {
            hasCriticalChain = true;
            var chainSummaries = BuildCriticalChainSummaries(traceMap.CriticalChains, findingById);
            likelyChain = chainSummaries.Count == 1
                ? $"{chainSummaries[0]}."
                : $"- {string.Join($"{Environment.NewLine}- ", chainSummaries)}";
        }
        else if (edges.Count > 0)
        {
            var chainCategories = LongestDirectedPathCategories(edges, findingById);
            likelyChain = chainCategories.Count > 1
                ? $"{string.Join(" → ", chainCategories)}."
                : "Correlated activity detected, but no full chain established.";
        }
        else
        {
            likelyChain = "Isolated findings — no correlated attack chain detected.";
        }

        // Generate recommendations from categories present
        var presentCategories = findings.Select(f => f.Category).Distinct(StringComparer.OrdinalIgnoreCase).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var recommendations = BuildRecommendations(presentCategories, findings);

        var markdown = BuildMarkdown(beats, likelyChain, hasCriticalChain, recommendations);

        return new IncidentStoryResult
        {
            Beats = beats,
            LikelyChain = likelyChain,
            HasCriticalChain = hasCriticalChain,
            Recommendations = recommendations,
            Markdown = markdown
        };
    }

    private static bool HasTimestamp(Finding finding) => finding.TimeRangeStart != DateTime.MinValue;

    /// <summary>
    /// Label assigned to snapshot (agent rule) beats. Not rendered by either consumer (markdown
    /// and the Avalonia view show snapshot beats narrative-only under "System Posture"); it
    /// serves as the per-category collapse key and a neutral value for any future consumer.
    /// </summary>
    private const string SnapshotTimestampLabel = "scan";

    private static string FormatTimestampLabel(DateTime timestamp, bool useDateInTimestamp)
    {
        if (timestamp == DateTime.MinValue)
        {
            return "unknown time";
        }

        return useDateInTimestamp
            ? timestamp.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)
            : timestamp.ToString("HH:mm", CultureInfo.InvariantCulture);
    }

    private static string VerbForCategory(string category) =>
        category switch
        {
            FindingCategories.Beaconing => "began",
            FindingCategories.LateralMovement => "appeared",
            FindingCategories.PrivilegeEscalation => "indicators were observed",
            FindingCategories.PortScan => "activity was detected",
            FindingCategories.Flood => "indicators were observed",
            FindingCategories.C2Channel => "channel activity was detected",
            FindingCategories.PolicyViolation => "breaches were detected",
            FindingCategories.Novelty => "novel activity was observed",
            FindingCategories.FlagAnomaly => "anomalies were observed",
            FindingCategories.MacSpoofing => "was detected",
            FindingCategories.InterfaceHopping => "was detected",
            FindingCategories.UnusualPacketSize => "packets were observed",
            FindingCategories.KernelModule => "module load was detected",
            FindingCategories.UserAccount => "anomalies were observed",
            FindingCategories.FilesystemAudit => "anomalies were detected",
            FindingCategories.CronJob => "suspicious job activity was detected",
            FindingCategories.PackageVulnerability => "vulnerable packages were found",
            FindingCategories.Container => "container anomalies were detected",
            FindingCategories.Kubernetes => "kubernetes anomalies were detected",
            FindingCategories.ThreatIntel => "threat intel matches were found",
            FindingCategories.Yara => "signature matches were found",
            FindingCategories.ProcessRuntime => "runtime anomalies were detected",
            _ => "was detected"
        };

    private static string NarrativeNameForCategory(string category) =>
        category switch
        {
            FindingCategories.Beaconing => "beaconing",
            FindingCategories.LateralMovement => "lateral movement",
            FindingCategories.PrivilegeEscalation => "privilege escalation",
            FindingCategories.PortScan => "port scan",
            FindingCategories.Flood => "flood / DoS",
            FindingCategories.C2Channel => "C2 channel",
            FindingCategories.PolicyViolation => "policy violation",
            FindingCategories.Novelty => "novelty",
            FindingCategories.FlagAnomaly => "flag anomaly",
            FindingCategories.MacSpoofing => "MAC spoofing",
            FindingCategories.InterfaceHopping => "interface hopping",
            FindingCategories.UnusualPacketSize => "unusual packet size",
            FindingCategories.KernelModule => "kernel module",
            FindingCategories.UserAccount => "user account",
            FindingCategories.FilesystemAudit => "filesystem audit",
            FindingCategories.CronJob => "cron job",
            FindingCategories.PackageVulnerability => "package vulnerability",
            FindingCategories.Container => "container",
            FindingCategories.Kubernetes => "kubernetes",
            FindingCategories.ThreatIntel => "threat intel",
            FindingCategories.Yara => "YARA",
            FindingCategories.ProcessRuntime => "process runtime",
            _ => NarrativeCase(CategoryDisplay.ToDisplayName(category))
        };

    /// <summary>
    /// Converts a display label into a sentence subject without damaging leading acronyms.
    /// For example, "Bootloader" becomes "bootloader", while "MAC" and "SSH Service"
    /// retain their acronym casing.
    /// </summary>
    private static string NarrativeCase(string displayName)
    {
        if (string.IsNullOrEmpty(displayName) ||
            displayName.Length < 2 ||
            !char.IsUpper(displayName[0]) ||
            !char.IsLower(displayName[1]))
        {
            return displayName;
        }

        return char.ToLowerInvariant(displayName[0]) + displayName[1..];
    }

    private static string DisplayNameForCategory(string category) =>
        category switch
        {
            FindingCategories.Beaconing => "C2",
            FindingCategories.LateralMovement => "Lateral Movement",
            FindingCategories.PrivilegeEscalation => "Privilege Escalation",
            FindingCategories.PortScan => "Port Scan",
            FindingCategories.Flood => "Flood / DoS",
            FindingCategories.C2Channel => "C2 Channel",
            FindingCategories.PolicyViolation => "Policy Violation",
            FindingCategories.Novelty => "Novelty",
            FindingCategories.FlagAnomaly => "Flag Anomaly",
            FindingCategories.MacSpoofing => "MAC Spoofing",
            FindingCategories.InterfaceHopping => "Interface Hopping",
            FindingCategories.UnusualPacketSize => "Unusual Packet Size",
            FindingCategories.KernelModule => "Kernel Module",
            FindingCategories.UserAccount => "User Account",
            FindingCategories.FilesystemAudit => "Filesystem Audit",
            FindingCategories.CronJob => "Cron Job",
            FindingCategories.PackageVulnerability => "Package Vulnerability",
            FindingCategories.Container => "Container",
            FindingCategories.Kubernetes => "Kubernetes",
            FindingCategories.ThreatIntel => "Threat Intel",
            FindingCategories.Yara => "YARA",
            FindingCategories.ProcessRuntime => "Process Runtime",
            _ => CategoryDisplay.ToDisplayName(category)
        };

    private static List<string> BuildCriticalChainSummaries(IReadOnlyList<CriticalChain> criticalChains, IReadOnlyDictionary<Guid, Finding> findingById)
    {
        var summaries = new List<string>();
        var includeHost = criticalChains.Count > 1;
        foreach (var chain in criticalChains)
        {
            var chainCategories = chain.FindingIds
                .Select(id => findingById.TryGetValue(id, out var f) ? DisplayNameForCategory(f.Category) : null)
                .Where(c => c != null)
                .Cast<string>()
                .ToList();

            if (chainCategories.Count == 0)
            {
                continue;
            }

            var chainText = string.Join(" → ", CollapseAdjacentDuplicates(chainCategories));
            summaries.Add(includeHost && !string.IsNullOrWhiteSpace(chain.Host) ? $"{chain.Host}: {chainText}" : chainText);
        }

        return summaries.Count > 0
            ? summaries
            : new List<string> { "critical chain detected, but referenced findings were unavailable" };
    }

    private static List<string> LongestDirectedPathCategories(IReadOnlyList<CorrelationEdge> edges, IReadOnlyDictionary<Guid, Finding> findingById)
    {
        var validEdges = edges
            .Where(e => findingById.ContainsKey(e.FromFindingId) && findingById.ContainsKey(e.ToFindingId))
            .ToList();

        if (validEdges.Count == 0)
        {
            return new List<string>();
        }

        var outgoing = validEdges
            .GroupBy(e => e.FromFindingId)
            .ToDictionary(
                g => g.Key,
                g => g.OrderBy(e => SortTime(findingById[e.ToFindingId])).ThenBy(e => e.ToFindingId).ToList());

        var candidateStarts = validEdges
            .SelectMany(e => new[] { e.FromFindingId, e.ToFindingId })
            .Distinct()
            .OrderBy(id => SortTime(findingById[id]))
            .ThenBy(id => id)
            .ToList();

        List<Guid> bestPath = new();
        foreach (var start in candidateStarts)
        {
            var path = LongestPathFrom(start, outgoing, findingById, new HashSet<Guid>());
            if (IsBetterPath(path, bestPath, findingById))
            {
                bestPath = path;
            }
        }

        var orderedCategories = bestPath
            .Select(id => DisplayNameForCategory(findingById[id].Category))
            .ToList();

        return CollapseAdjacentDuplicates(orderedCategories);
    }

    private static List<Guid> LongestPathFrom(
        Guid current,
        IReadOnlyDictionary<Guid, List<CorrelationEdge>> outgoing,
        IReadOnlyDictionary<Guid, Finding> findingById,
        HashSet<Guid> visited)
    {
        visited.Add(current);
        var best = new List<Guid> { current };

        if (outgoing.TryGetValue(current, out var nextEdges))
        {
            foreach (var edge in nextEdges)
            {
                if (visited.Contains(edge.ToFindingId))
                {
                    continue;
                }

                var candidate = new List<Guid> { current };
                candidate.AddRange(LongestPathFrom(edge.ToFindingId, outgoing, findingById, visited));
                if (IsBetterPath(candidate, best, findingById))
                {
                    best = candidate;
                }
            }
        }

        visited.Remove(current);
        return best;
    }

    private static bool IsBetterPath(IReadOnlyList<Guid> candidate, IReadOnlyList<Guid> currentBest, IReadOnlyDictionary<Guid, Finding> findingById)
    {
        if (candidate.Count != currentBest.Count)
        {
            return candidate.Count > currentBest.Count;
        }

        if (currentBest.Count == 0)
        {
            return true;
        }

        var candidateStart = SortTime(findingById[candidate[0]]);
        var bestStart = SortTime(findingById[currentBest[0]]);
        return candidateStart < bestStart;
    }

    private static DateTime SortTime(Finding finding) =>
        HasTimestamp(finding) ? finding.TimeRangeStart : DateTime.MaxValue;

    private static List<string> CollapseAdjacentDuplicates(List<string> items)
    {
        var result = new List<string>();
        string? previous = null;
        foreach (var item in items)
        {
            if (!string.Equals(item, previous, StringComparison.Ordinal))
            {
                result.Add(item);
                previous = item;
            }
        }
        return result;
    }

    private static List<string> BuildRecommendations(HashSet<string> categories, IReadOnlyList<Finding> findings)
    {
        var recommendations = new List<string>();

        if (categories.Contains(FindingCategories.Beaconing) || categories.Contains(FindingCategories.C2Channel))
        {
            var destinations = findings
                .Where(f => IsCategory(f, FindingCategories.Beaconing) || IsCategory(f, FindingCategories.C2Channel))
                .Select(f => f.Target)
                .Distinct()
                .Take(3)
                .ToList();
            var destText = destinations.Count > 0 ? $" ({string.Join(", ", destinations)})" : "";
            recommendations.Add($"Block outbound destinations{destText}.");
        }

        if (categories.Contains(FindingCategories.LateralMovement))
        {
            var hosts = findings
                .Where(f => IsCategory(f, FindingCategories.LateralMovement))
                .Select(f => f.SourceHost)
                .Distinct()
                .Take(3)
                .ToList();
            var hostText = hosts.Count > 0 ? $" on {string.Join(", ", hosts)}" : "";
            recommendations.Add($"Preserve logs and inspect lateral movement paths{hostText}.");
        }

        if (categories.Contains(FindingCategories.PrivilegeEscalation))
        {
            recommendations.Add("Inspect account changes, sudoers, and PAM configuration.");
        }

        if (categories.Contains(FindingCategories.PortScan))
        {
            recommendations.Add("Review firewall rules and restrict exposed ports.");
        }

        if (categories.Contains(FindingCategories.Flood))
        {
            recommendations.Add("Consider rate-limiting and DDoS mitigation.");
        }

        if (categories.Contains(FindingCategories.PolicyViolation))
        {
            recommendations.Add("Enforce baseline policies and review exceptions.");
        }

        if (categories.Contains(FindingCategories.UserAccount) || categories.Contains(FindingCategories.FilesystemAudit))
        {
            recommendations.Add("Audit user sessions and file integrity.");
        }

        if (categories.Contains(FindingCategories.PackageVulnerability))
        {
            recommendations.Add("Patch or quarantine vulnerable packages.");
        }

        if (categories.Contains(FindingCategories.Container) || categories.Contains(FindingCategories.Kubernetes))
        {
            recommendations.Add("Review container runtime policies and image provenance.");
        }

        if (recommendations.Count == 0)
        {
            recommendations.Add("Review findings and determine appropriate containment steps.");
        }

        return recommendations;
    }

    private static bool IsCategory(Finding f, string category) =>
        string.Equals(f.Category, category, StringComparison.OrdinalIgnoreCase);

    private static string BuildMarkdown(IReadOnlyList<StoryBeat> beats, string likelyChain, bool hasCriticalChain, IReadOnlyList<string> recommendations)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Incident Story");
        sb.AppendLine();

        if (hasCriticalChain)
        {
            sb.AppendLine("> ⚠️ **Critical attack chain detected**");
            sb.AppendLine();
        }

        // Chain summary and recommendations come first so they stay above the fold;
        // the (potentially long) timeline follows.
        sb.AppendLine("## Likely Chain");
        sb.AppendLine();
        sb.AppendLine(likelyChain);
        sb.AppendLine();

        if (recommendations.Count > 0)
        {
            sb.AppendLine("## Recommended Response");
            sb.AppendLine();
            foreach (var rec in recommendations)
            {
                sb.AppendLine($"- {rec}");
            }
            sb.AppendLine();
        }

        var snapshotBeats = beats.Where(b => b.Kind == StoryBeatKind.Snapshot).ToList();
        var eventBeats = beats.Where(b => b.Kind == StoryBeatKind.Event).ToList();

        // Configuration snapshots are point-in-time (scan time, not events); surface them as a
        // distinct "System Posture" section above the chronological event timeline. Each section
        // is emitted only when it has beats.
        if (snapshotBeats.Count > 0)
        {
            sb.AppendLine("## System Posture");
            sb.AppendLine();
            sb.AppendLine("Configuration findings from the latest audit (point-in-time, not events).");
            sb.AppendLine();
            foreach (var beat in snapshotBeats)
            {
                sb.AppendLine($"- {beat.Narrative}");
            }
            sb.AppendLine();
        }

        if (eventBeats.Count > 0)
        {
            sb.AppendLine("## Timeline");
            sb.AppendLine();
            foreach (var beat in eventBeats)
            {
                sb.AppendLine($"- **{beat.TimestampLabel}** — {beat.Narrative}");
            }
            sb.AppendLine();
        }

        return sb.ToString();
    }

    /// <summary>
    /// Mutable accumulation state for collapsing same-timestamp, same-category beats
    /// into a single beat with a finding count.
    /// </summary>
    private sealed class BeatAccumulator
    {
        public required StoryBeat Beat { get; set; }

        /// <summary>The narrative sentence without the trailing period or count suffix.</summary>
        public required string Sentence { get; init; }

        public int Count { get; set; } = 1;
    }
}
