# Code Patterns

---

## Pattern 1: Strategy Pattern -- IDetector

```csharp
public sealed class BeaconingDetector : IDetector
{
    public DetectionResult Detect(
        IReadOnlyList<UnifiedEvent> events,
        AnalysisProfile profile,
        CancellationToken cancellationToken)
}
```

**Why:** Detectors are interchangeable. The engine iterates detectors through dedicated `IDetector` loops (baseline, Linux-specific, and advanced) -- each using the same interface contract. Adding a new detector does not require changes to the orchestrator.

**Security Angle:** Modularity is a security property. New detection rules don't risk breaking existing ones.

---

## Pattern 2: Parameter Object -- AnalysisProfile Record

```csharp
public sealed record AnalysisProfile
{
    public bool EnableBeaconing { get; init; }
    public int BeaconMinEvents { get; init; }
    public double BeaconStdDevThreshold { get; init; }
    public int BeaconMinIntervalSeconds { get; init; }
    public int BeaconMaxIntervalSeconds { get; init; }
    public int BeaconMaxSamplesPerTuple { get; init; }
    public int BeaconMinDurationSeconds { get; init; }
    public double BeaconTrimPercent { get; init; }
}
```

**Why:** Eight beaconing-specific parameters (one enable toggle plus seven thresholds), all externalized. No hardcoded thresholds. Teams tune detection by choosing a profile, not by modifying code. The `record` type ensures immutability -- profiles cannot drift at runtime.

**Security Angle:** Configuration-driven security. Detection sensitivity adapts to the environment without code deployment.

---

## Pattern 3: Structured Finding Output

```csharp
var first = ordered.First();
var last = ordered.Last();

findings.Add(new Core.Finding
{
    Category = FindingCategories.Beaconing,
    Severity = Core.Severity.Medium,
    SourceHost = group.Key.SourceIP,
    Target = $"{group.Key.DestinationIP}:{group.Key.DestinationPort}",
    TimeRangeStart = first.Timestamp,
    TimeRangeEnd = last.Timestamp,
    ShortDescription = $"Regular beaconing from {group.Key.SourceIP}",
    Details = $"Average interval ~{mean:F1}s, std dev ~{stdDev:F1}s over {ordered.Count} events."
});
```

**Why:** Each documented field serves an analyst workflow: Category for filtering, Severity for triage, SourceHost for identification, TimeRange for timeline context, Details for investigation.

**Downstream behavior:** RiskEscalator raises to Critical if same host has Beaconing + LateralMovement. MinSeverityToShow filters findings at the engine level before they reach the UI.

---

## Pattern 4: Early Exit Gates

```csharp
if (!profile.EnableBeaconing || events.Count == 0)
    return DetectionResult.Empty;
```

Per-tuple gates inside the group loop:

```csharp
if (ordered.Count < profile.BeaconMinEvents) continue;
if (durationSeconds < profile.BeaconMinDurationSeconds) continue;
if (intervals.Count == 0) continue;
if (mean < profile.BeaconMinIntervalSeconds || mean > profile.BeaconMaxIntervalSeconds) continue;
if (stdDev > profile.BeaconStdDevThreshold) continue;
```

**Why:** Each gate prevents unnecessary computation. Channels that cannot possibly trigger beaconing are filtered before expensive statistical analysis. During Step C (Order + Cap), the detector optionally limits samples to the most recent N via `BeaconMaxSamplesPerTuple` (when > 0) before the min-events gate is evaluated. Between the empty-intervals gate and the statistical gates, intervals are sorted and trimmed via `TrimIntervals` before computing mean and standard deviation. Cancellation tokens add cooperative cancellation per group.

**Security Angle:** Resource protection. These gates reduce unnecessary work on channels that clearly cannot trigger.

---

## Pattern 5: Symmetric Trimmed Mean

```csharp
private static IReadOnlyList<double> TrimIntervals(
    IReadOnlyList<double> sortedIntervals, double trimPercent)
{
    if (sortedIntervals.Count <= 2 || trimPercent <= 0)
        return sortedIntervals;

    var trimCount = (int)Math.Ceiling(sortedIntervals.Count * trimPercent);
    if (trimCount == 0)
        return sortedIntervals;

    var start = trimCount;
    var length = sortedIntervals.Count - (2 * trimCount);
    if (length < 2)
        return sortedIntervals;

    return sortedIntervals.Skip(start).Take(length).ToList();
}
```

**Why:** Isolated helper method with clear contract. Symmetric removal from both ends prevents directional bias. The `Ceiling` ensures at least one interval is trimmed when the count warrants it.

**Security Angle:** Robustness against benign jitter and occasional anomalies. It improves tolerance, but determined jitter-based evasion still exists.

---

## Security Takeaways

1. **Strategy pattern = modular security** -- detectors are interchangeable and independently testable
2. **Parameter objects = tunable security** -- sensitivity adapts to the environment without code changes
3. **Structured findings = analyst efficiency** -- each documented field serves a triage workflow
4. **Early exits = resource protection** -- low-value work is skipped before the full statistical path runs
