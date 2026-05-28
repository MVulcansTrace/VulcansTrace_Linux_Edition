# Novelty Detection — Detection Algorithm

## Security Problem

Novelty detection identifies external destinations that appear no more than `maxOccurrences` times (default 1, i.e. strict singletons) across the entire event dataset. The challenge is that this determination requires global knowledge — an event cannot be classified as "novel" until every other event has been examined. This necessitates a two-pass approach.

---

## Implementation Overview

```
         Raw Events
             |
             v
    ┌─────────────────────┐
    │ Step A: Guard Check  │  Skip if disabled or empty
    └────────┬────────────┘
             v
    ┌─────────────────────┐
    │ Step B: Filter       │  External destinations only
    └────────┬────────────┘
             v
    ┌─────────────────────┐
    │ Step C: Pass 1       │  Build frequency dictionary
    │   (Count)            │  Key: (DestIP, DestPort)
    └────────┬────────────┘
             v
     ┌─────────────────────┐
     │ Step D: Pass 2       │  Flag events with count ≤ maxOccurrences
     │   (Singletons)       │  Group singletons by source IP
     └────────┬────────────┘
              v
     ┌─────────────────────┐
     │ Step E: Report       │  Emit one finding per source IP
     └─────────────────────┘
```

---

### Step A — Guard Check

```csharp
if (!profile.EnableNovelty || events.Count == 0)
    return DetectionResult.Empty;
```

Returns immediately if novelty detection is disabled (Low profile) or the event list is empty.

---

### Step B — Filter to External Destinations

```csharp
var externalEntries = events.Where(e => IpClassification.IsExternal(e.DestinationIP)).ToList();
if (externalEntries.Count == 0)
    return DetectionResult.Empty;
```

Only outbound connections to external (public) destinations are considered. Internal traffic is excluded because internal singletons are common and rarely security-relevant (e.g., one-time service discovery broadcasts).

The early exit on empty results avoids allocating the frequency dictionary when no external events exist.

---

### Step C — Pass 1: Build Frequency Dictionary

```csharp
var counts = externalEntries
    .GroupBy(e => (e.DestinationIP, e.DestinationPort))
    .ToDictionary(g => g.Key, g => g.Count());
```

The frequency dictionary maps each unique (DestIP, DestPort) pair to its occurrence count. This uses C# tuple equality for the composite key — two events with the same destination IP but different ports produce separate entries.

The `GroupBy` + `ToDictionary` pattern is a LINQ idiom that builds the complete frequency table in a single expression.

---

### Step D — Pass 2: Extract Singletons and Group by Source

```csharp
var bySource = new Dictionary<string, List<(string DstIP, int DstPort, DateTime Timestamp)>>();

foreach (var e in externalEntries)
{
    cancellationToken.ThrowIfCancellationRequested();

    var key = (e.DestinationIP, e.DestinationPort);
    if (counts[key] > maxOccurrences)
        continue;

    if (!bySource.TryGetValue(e.SourceIP, out var list))
    {
        list = new List<(string, int, DateTime)>();
        bySource[e.SourceIP] = list;
    }
    list.Add((e.DestinationIP, e.DestinationPort, e.Timestamp));
}
```

Each external event is revisited. Its (DestIP, DestPort) key is looked up in the frequency dictionary. Only events with count ≤ `maxOccurrences` pass through (default 1, strict singletons). The dictionary lookup is O(1) via hash-based indexing. Novel events are then grouped by source IP into a `bySource` dictionary for aggregated reporting.

---

### Step E — Emit Findings Per Source

```csharp
foreach (var kvp in bySource)
{
    cancellationToken.ThrowIfCancellationRequested();

    var source = kvp.Key;
    var destinations = kvp.Value;
    var minTime = destinations.Min(d => d.Timestamp);
    var maxTime = destinations.Max(d => d.Timestamp);
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
}

return new DetectionResult(findings);
```

Singletons are grouped by source IP — each source produces a single finding. The `Target` field lists up to 5 destination `IP:Port` pairs (comma-separated), with `"..."` appended if there are more. The `minTime`/`maxTime` across all of the source's singletons provides the time range. The severity is deliberately `Low` because singletons are suggestive but not conclusive evidence of malicious activity.

---

## Complexity And Behavior

| Aspect | Detail |
|---|---|
| Pass 1 (frequency) | O(n) — one GroupBy + ToDictionary |
| Pass 2 (singletons) | O(n) — one iteration with O(1) dictionary lookup per event |
| Total time | O(n) — two linear passes |
| Space | O(u) — u = number of unique (IP, Port) pairs |
| Findings | O(s) — s = number of singleton pairs (potentially large) |

---

## Implementation Evidence

- [NoveltyDetector.cs](../../../../../VulcansTrace.Linux.Engine/Detectors/NoveltyDetector.cs) — full implementation (83 lines)
- [NoveltyDetectorTests.cs](../../../../../VulcansTrace.Linux.Tests/Detectors/Baseline/NoveltyDetectorTests.cs) — test coverage (74 lines)
