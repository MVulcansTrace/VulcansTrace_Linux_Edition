# Code Patterns: Linux Deep Inspection

## The Security Problem

Security detectors must be both correct and resilient. A detector that crashes on malformed input, produces inconsistent results on re-runs, or silently drops data when under load is worse than no detector at all — it provides false confidence. The five Linux Deep Inspection detectors share several recurring code patterns that support reliability, transparency, and safe cancellation.

---

## Implementation Overview

| Pattern | Detectors Using It | Purpose |
|---|---|---|
| Guard clause | All 5 | Early exit on disabled/empty input |
| `LinuxSpecific` metadata access via `GetValueOrDefault` | All 5 | Safe dictionary access with default fallback |
| Cooperative cancellation | All 5 | Safe shutdown on large inputs |
| LINQ grouping pipeline | MAC Spoofing, Interface Hopping | Declarative per-IP analysis |
| Sliding window scan | MAC Spoofing, Interface Hopping | Time-bounded maximum distinct count |
| `Dictionary` timestamp tracking | Kernel Module | Per-module timestamp collection with time range reporting |
| Two-phase analysis with grouping | Packet Size | Per-packet + aggregate with sample gate |
| Aggregation by composite key | Flag Anomaly, Packet Size | One finding per group, not per event |

---

## How It Works (Technical)

### Guard Clause

```csharp
if (!profile.EnableFlagAnomaly || events.Count == 0)
    return DetectionResult.Empty;
```

Every detector begins with an identical guard pattern. The first check is whether the detector is enabled via the `AnalysisProfile` boolean flag. The second check is whether there are events to process. If either condition fails, the detector returns an empty `DetectionResult` without allocating any data structures. This pattern is consistent across all five detectors and across the entire VulcansTrace detector suite.

---

### `LinuxSpecific` Metadata Access

```csharp
var flags = evt.LinuxSpecific.GetValueOrDefault("Flags", "").ToUpper();
var mac = FirewallLogRegex.NormalizeMacField(e.LinuxSpecific.GetValueOrDefault("MAC", ""));
var lengthStr = evt.LinuxSpecific.GetValueOrDefault("Length", "");
```

All five detectors use `GetValueOrDefault` to access `LinuxSpecific` metadata. This pattern provides two safety guarantees: (1) if the key is missing from the dictionary, a default value (typically `""`) is returned instead of throwing `KeyNotFoundException`, and (2) the default value is chosen to be falsy so downstream checks (empty string, failed `int.TryParse`) produce no findings rather than exceptions. This is critical because not all log formats populate all metadata fields. The MAC spoofing detector additionally normalizes MAC addresses via `FirewallLogRegex.NormalizeMacField` before comparison, ensuring format-consistent matching.

---

### Cooperative Cancellation

```csharp
cancellationToken.ThrowIfCancellationRequested();
```

Every detector checks cancellation at each loop iteration — the outer `foreach` for per-event detectors (FlagAnomaly, KernelModule, PacketSize) and the outer per-IP-group `foreach` for grouping detectors (MAC Spoofing, Interface Hopping). `ThrowIfCancellationRequested` throws `OperationCanceledException` if cancellation was requested. Because findings are accumulated in local `List<Finding>` variables, a cancelled operation abandons partial results rather than returning incomplete data.

---

### LINQ Grouping Pipeline

```csharp
var byIp = events.GroupBy(e => e.SourceIP);

foreach (var ipGroup in byIp)
{
    // ... per-IP analysis
}
```

MAC Spoofing and Interface Hopping detectors use `GroupBy(SourceIP)` to partition events by source IP before analysis. This is the standard VulcansTrace pattern for per-host detection — each group represents all observed behavior from a single source, and the detector's logic operates on the group as a unit.

---

### Sliding Window Scan

```csharp
var counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
var distinct = 0;
var start = 0;
var bestDistinct = 0;

for (var end = 0; end < ordered.Count; end++)
{
    // Add item at position end
    // Shrink window from left while time span > windowMinutes
    // Track best (maximum distinct) window seen
}

if (bestDistinct > 1)
{
    // Emit finding with items from best window
}
```

Both the MAC Spoofing and Interface Hopping detectors use an identical two-pointer sliding window pattern after grouping by `SourceIP` and ordering by timestamp. As the `end` pointer advances, each new value (MAC address or interface name) is added to the window's count dictionary. The `start` pointer advances to shrink the window whenever the time span exceeds the configured window (default 5 minutes), decrementing counts and removing values that fall to zero. The window with the most distinct values is tracked, and a finding is emitted only if that maximum exceeds 1. This pattern finds the tightest cluster of diversity for the IP while avoiding false positives from legitimate long-term changes.

---

### `Dictionary` Timestamp Tracking

```csharp
var moduleTimestamps = new Dictionary<string, List<DateTime>>();

void RecordModule(string moduleName, DateTime timestamp)
{
    if (!moduleTimestamps.TryGetValue(moduleName, out var list))
    {
        list = new List<DateTime>();
        moduleTimestamps[moduleName] = list;
    }
    list.Add(timestamp);
}

// ... after all events processed ...
foreach (var (module, timestamps) in moduleTimestamps)
{
    findings.Add(new Core.Finding
    {
        TimeRangeStart = timestamps.Min(),
        TimeRangeEnd = timestamps.Max(),
        // ...
    });
}
```

The KernelModuleDetector uses a `Dictionary<string, List<DateTime>>` to collect per-module timestamps during the per-event scan pass. Each matching event appends its timestamp to the module's list. After all events are processed, one finding is emitted per unique module, with the time range computed from the module's own timestamps (not the full event set). This provides more accurate time range reporting than deduplication-only approaches.

---

### Two-Phase Analysis with Grouping

```csharp
// Phase 1: Per-packet (grouped by SrcIP, DstIP pairs)
if (length > largeThreshold)
{
    var key = (evt.SourceIP, evt.DestinationIP);
    largeGroups[key].Add((length, evt.Timestamp));
}

if (length > 0 && length < smallThreshold)
{
    var key = (evt.SourceIP, evt.DestinationIP);
    smallGroups[key].Add((length, evt.Timestamp));
}

// Phase 2: Aggregate (grouped by SrcIP, DstIP, DstPort, Proto tuples)
foreach (var kvp in sizeByTuple)
{
    if (tupleEvents.Count < minForAnalysis)
        continue;

    // Statistical analysis...
}
```

The UnusualPacketSizeDetector splits its analysis into two phases. Phase 1 runs on every event and checks absolute thresholds — these are deterministic, per-packet checks grouped by `(SrcIP, DstIP)` pairs so that one finding is emitted per pair rather than per packet. Phase 2 groups by full `(SrcIP, DstIP, DstPort, Proto)` tuples and runs only when sufficient data is available (≥ `minForAnalysis` packets per tuple). The sample gate prevents Phase 2 from producing noisy, unreliable findings on small traffic bursts.

---

### Aggregation by Composite Key

```csharp
// FlagAnomaly: aggregate by (SourceIP, AnomalyType)
var groups = new Dictionary<(string SourceIP, string AnomalyType), List<UnifiedEvent>>();

void Aggregate(UnifiedEvent evt, string anomalyType)
{
    var key = (evt.SourceIP, anomalyType);
    if (!groups.TryGetValue(key, out var list))
    {
        list = new List<UnifiedEvent>();
        groups[key] = list;
    }
    list.Add(evt);
}
```

The FlagAnomalyDetector aggregates events by `(SourceIP, AnomalyType)` during the per-event scan, then emits one finding per group after all events are processed. This prevents alert fatigue — instead of one finding per matching event, analysts see one finding per source+type combination with a summary of all targets. The PacketSizeDetector uses a similar pattern with `(SrcIP, DstIP)` and `(SrcIP, DstIP, DstPort, Proto)` composite keys.

---

## Implementation Evidence

- [FlagAnomalyDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/FlagAnomalyDetector.cs) — guard clause, metadata access, cancellation, composite-key aggregation (86 lines)
- [MacSpoofingDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/MacSpoofingDetector.cs) — guard clause, LINQ grouping, sliding window, cancellation (121 lines)
- [KernelModuleDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/KernelModuleDetector.cs) — guard clause, Dictionary timestamp tracking, cancellation (96 lines)
- [InterfaceHoppingDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/InterfaceHoppingDetector.cs) — guard clause, LINQ grouping, sliding window, cancellation (117 lines)
- [UnusualPacketSizeDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/UnusualPacketSizeDetector.cs) — guard clause, two-phase analysis, grouping, sample gate (173 lines)
- [FlagAnomalyDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/Linux/FlagAnomalyDetectorTests.cs) — validates guard, flag combinations, protocol filtering (422 lines)
- [MacSpoofingDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/Linux/MacSpoofingDetectorTests.cs) — validates grouping, MAC normalization, sliding window (643 lines)
- [KernelModuleDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/Linux/KernelModuleDetectorTests.cs) — validates signature matching, timestamp tracking (630 lines)
- [InterfaceHoppingDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/Linux/InterfaceHoppingDetectorTests.cs) — validates sliding window, multi-interface detection (553 lines)
- [UnusualPacketSizeDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/Linux/UnusualPacketSizeDetectorTests.cs) — validates per-packet and aggregate analysis (665 lines)

---

## Security Takeaways

1. Guard clauses prevent any detector from processing data when disabled — zero resource consumption for unused detectors
2. `GetValueOrDefault` on `LinuxSpecific` ensures detectors degrade gracefully when metadata is missing — no exceptions, just empty findings
3. Cooperative cancellation at every loop iteration prevents runaway processing on large log files without corrupting partial results
4. The `Dictionary<string, List<DateTime>>` pattern in KernelModuleDetector provides per-module time ranges, giving analysts accurate temporal context for each detected capability
5. The two-phase analysis pattern in UnusualPacketSizeDetector provides immediate per-pair threshold alerting while deferring statistical analysis until sufficient data is available per tuple
6. The sliding window pattern in MacSpoofingDetector and InterfaceHoppingDetector finds the tightest cluster of diversity while avoiding false positives from legitimate long-term changes
