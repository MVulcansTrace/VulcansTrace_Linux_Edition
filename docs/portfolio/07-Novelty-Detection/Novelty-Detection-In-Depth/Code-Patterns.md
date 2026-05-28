# Novelty Detection — Code Patterns

## Security Problem

Novelty detection must process the entire event dataset to build a complete frequency table before any event can be classified as a singleton. The implementation uses LINQ idioms and hash-based lookups to keep the two-pass algorithm efficient and readable.

---

## Implementation Overview

| Pattern | Location | Purpose |
|---|---|---|
| Guard clause | Lines 10-11 | Early return when disabled or empty |
| Early exit on empty filter | Lines 13-15 | Skip frequency building if no external events |
| LINQ GroupBy + ToDictionary | Lines 17-19 | Frequency table in one expression |
| Tuple composite key | Lines 18, 29 | (DestIP, DestPort) grouping |
| Dictionary lookup | Line 28 | O(1) singleton check |
| Source grouping | Lines 21, 31-36 | Group singletons by source IP |
| Per-source finding | Lines 41-79 | Aggregated finding per source with comma-separated targets |

---

## How It Works

### Guard Clause Pattern

```csharp
if (!profile.EnableNovelty || events.Count == 0)
    return DetectionResult.Empty;
```

Standard guard clause. In the Low profile, `EnableNovelty` is false, so the detector returns immediately — zero cost, zero output.

---

### Filter with Early Exit

```csharp
var externalEntries = events.Where(e => IpClassification.IsExternal(e.DestinationIP)).ToList();
if (externalEntries.Count == 0)
    return DetectionResult.Empty;
```

The `ToList()` materializes the filtered result so it can be iterated twice (once for counting, once for singleton extraction). The early exit avoids dictionary allocation when all traffic is internal.

---

### LINQ GroupBy + ToDictionary for Frequency Table

```csharp
var counts = externalEntries
    .GroupBy(e => (e.DestinationIP, e.DestinationPort))
    .ToDictionary(g => g.Key, g => g.Count());
```

This is a common LINQ idiom for building frequency tables:

- `GroupBy` partitions events by the composite key `(DestIP, DestPort)` — C# value tuples provide built-in equality and hashing
- `ToDictionary` converts each group into a key-value pair where the key is the (IP, Port) tuple and the value is the group's count
- The result is a `Dictionary<(string, int), int>` with O(1) lookup

---

### Tuple Key for Singleton Check

```csharp
var maxOccurrences = profile.NoveltyMaxGlobalOccurrences > 0 ? profile.NoveltyMaxGlobalOccurrences : 1;
// ...
var key = (e.DestinationIP, e.DestinationPort);
if (counts[key] > maxOccurrences)
    continue;
```

The same tuple structure used to build the dictionary is used to look up each event's frequency. C# value tuples provide structural equality, so `(e.DestinationIP, e.DestinationPort)` matches the key even though it's a different tuple instance.

The `counts[key]` indexer (rather than `TryGetValue`) is safe because every external event's (DestIP, DestPort) pair was included in the dictionary during Pass 1. The threshold `maxOccurrences` defaults to 1 (strict singletons) but can be raised to catch near-singletons.

---

### Per-Source Finding with Aggregated Target List

```csharp
var uniqueDests = destinations
    .Select(d => (d.DstIP, d.DstPort))
    .Distinct()
    .ToList();
var sampleTargets = uniqueDests
    .Select(d => $"{d.DstIP}:{d.DstPort}")
    .Take(5)
    .ToList();
var targetList = sampleTargets.Count < uniqueDests.Count
    ? $"{string.Join(", ", sampleTargets)}, ..."
    : string.Join(", ", sampleTargets);

var occurrenceWord = maxOccurrences == 1 ? "exactly once" : $"at most {maxOccurrences} time(s)";

findings.Add(new Core.Finding
{
    Category = FindingCategories.Novelty,
    Severity = Core.Severity.Low,
    SourceHost = source,
    Target = targetList,
    TimeRangeStart = minTime,
    TimeRangeEnd = maxTime,
    ShortDescription = $"{uniqueDests.Count} novel destination(s) from {source}",
    Details = $"Source {source} contacted {uniqueDests.Count} external destination(s) {occurrenceWord}. This may indicate reconnaissance or testing of exfiltration channels."
});
```

Singletons are grouped by source IP — each source produces one finding. The `Target` field is a comma-separated list of up to 5 `IP:Port` pairs, with `"..."` appended if there are more. The time range spans `minTime` to `maxTime` across all of the source's singletons, providing temporal context for the aggregated finding.

---

## Implementation Evidence

- [NoveltyDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/NoveltyDetector.cs) — all patterns in context (83 lines)
- [NoveltyDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/Baseline/NoveltyDetectorTests.cs) — validates two-pass behavior (74 lines)

---

## Security Takeaways

- The two-pass pattern ensures correct singleton identification — no false positives from premature classification
- The LINQ GroupBy + ToDictionary idiom is a concise, auditable way to build frequency tables
- Tuple-based composite keys provide correct service-level granularity without custom equality comparers
- The dictionary indexer (not TryGetValue) is safe because the filter and dictionary use the same population — demonstrating defensive correctness
