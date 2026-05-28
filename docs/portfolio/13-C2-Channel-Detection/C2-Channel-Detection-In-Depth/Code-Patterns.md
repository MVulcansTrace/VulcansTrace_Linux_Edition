# Code Patterns

---

## Pattern 1: Strategy Pattern -- IDetector

```csharp
public sealed class C2ChannelDetector : IDetector
{
    public DetectionResult Detect(
        IReadOnlyList<UnifiedEvent> events,
        AnalysisProfile profile,
        CancellationToken cancellationToken)
}
```

**Why:** Detectors are interchangeable. The engine iterates all detectors through a single `IDetector` loop -- modular, extensible pipeline. Adding a new detector does not require changes to the orchestrator.

**Security Angle:** Modularity is a security property. New detection rules don't risk breaking existing ones. The C2 Channel detector runs alongside Beaconing without interference.

---

## Pattern 2: Parameter Object -- AnalysisProfile Record

```csharp
public sealed record AnalysisProfile
{
    public bool EnableC2Detection { get; init; }
    public double C2ToleranceSeconds { get; init; }
    public int C2MinIntervalSeconds { get; init; }
    public int C2MaxIntervalSeconds { get; init; }
    public int C2MinOccurrences { get; init; }
    public int C2MinPatternEvents { get; init; }
    public int C2MinGroupSize { get; init; }
}
```

**Why:** Seven C2-specific parameters (one enable toggle plus six thresholds), all externalized. No hardcoded thresholds. Teams tune detection by choosing a profile, not by modifying code. The `record` type ensures immutability -- profiles cannot drift at runtime.

**Security Angle:** Configuration-driven security. Detection sensitivity adapts to the environment without code deployment.

---

## Pattern 3: Structured Finding Output

```csharp
findings.Add(new Core.Finding
{
    Category = FindingCategories.C2Channel,
    Severity = Core.Severity.High,
    SourceHost = orderedEvents.First().SourceIP,
    Target = $"{orderedEvents.First().DestinationIP}:{orderedEvents.First().DestinationPort}",
    TimeRangeStart = minTime,
    TimeRangeEnd = maxTime,
    ShortDescription = $"Potential C2 channel detected: {connectionKey}",
    Details = $"Detected {patternEvents.Count} events with approximately {interval}s intervals (tolerance: +/-{tolerance}s). " +
              $"This pattern suggests periodic communication that may indicate a C2 channel."
});
```

**Why:** Every field serves an analyst workflow: Category for filtering, Severity for triage, SourceHost for blocking, TimeRange for correlation, Details for investigation. The Details string includes the interval, tolerance, and event count -- the three key parameters for understanding the finding.

**Security Angle:** The finding communicates the detection rationale. An analyst sees "approximately 60s intervals with tolerance +/-5s" and can immediately assess whether this matches known C2 behavior.

---

## Pattern 4: Early Exit Gates

```csharp
if (!profile.EnableC2Detection || events.Count == 0)
    return DetectionResult.Empty;
if (profile.C2ToleranceSeconds <= 0)
    return DetectionResult.Empty;
if (interval < profile.C2MinIntervalSeconds || interval > profile.C2MaxIntervalSeconds)
    continue;
if (patternEvents.Count >= profile.C2MinPatternEvents)
```

**Why:** Each gate prevents unnecessary computation. Empty inputs and disabled detectors return immediately. Invalid configurations fail safe. Channels with intervals outside the C2 range are skipped before pattern reconstruction.

**Security Angle:** Resource protection and fail-safe behavior. Invalid configurations produce no findings rather than garbage findings.

---

## Pattern 5: Greedy Delta Clustering

```csharp
var sortedDeltas = timeDeltas
    .Select((delta, index) => new DeltaSample(delta, index))
    .OrderBy(sample => sample.Delta)
    .ToList();

var groups = new List<DeltaGroup>();
var maxSpan = tolerance * 2;

for (var start = 0; start < sortedDeltas.Count;)
{
    var samples = new List<DeltaSample> { sortedDeltas[start] };
    var end = start + 1;
    while (end < sortedDeltas.Count && sortedDeltas[end].Delta - sortedDeltas[start].Delta <= maxSpan)
    {
        samples.Add(sortedDeltas[end]);
        end++;
    }

    if (samples.Count >= minOccurrences)
    {
        groups.Add(new DeltaGroup(
            samples.Average(sample => sample.Delta),
            samples.Select(sample => sample.Index).ToList()));
        start = end;
    }
    else
    {
        start++;
    }
}
```

**Why:** Deltas are sorted, then a greedy sliding window groups consecutive values within `tolerance * 2`. If the window has enough samples, it becomes a group with the average delta as the interval; otherwise the window advances by one. This clustering approach finds natural density peaks in the delta distribution without requiring exact bucket alignment.

**Security Angle:** This is the statistical heart of the detector. The tolerance parameter controls the maximum span: larger tolerance = wider window = more forgiving grouping. The profile controls this trade-off. Sorting ensures O(n log n) complexity and the sliding window efficiently finds clusters.

---

## Pattern 6: Pattern Reconstruction

```csharp
var patternEvents = new HashSet<UnifiedEvent>();
foreach (var index in deltaGroup.Indices)
{
    patternEvents.Add(orderedEvents[index]);
    patternEvents.Add(orderedEvents[index + 1]);
}
```

**Why:** The clustering step preserved the original delta indices. Reconstruction traces directly from those indices to the events that produced the deltas -- no re-scanning required. Both events for each delta (at index and index+1) are added to the pattern set. The `HashSet` automatically deduplicates events when consecutive deltas both match.

**Security Angle:** Evidence-based findings. The reconstructed pattern events become the finding's time range and count, giving analysts concrete data rather than abstract statistics. Using precomputed indices eliminates repeated O(n) scans when multiple groups survive the prior gates.

---

## Security Takeaways

1. **Strategy pattern = modular security** -- detectors are interchangeable and independently testable
2. **Parameter objects = tunable security** -- sensitivity adapts to the environment without code changes
3. **Structured findings = analyst efficiency** -- every field serves a triage workflow
4. **Early exits = resource protection** -- low-value work is skipped before pattern reconstruction runs
5. **Pattern reconstruction = evidence-based alerts** -- findings contain actual events, not just statistics
