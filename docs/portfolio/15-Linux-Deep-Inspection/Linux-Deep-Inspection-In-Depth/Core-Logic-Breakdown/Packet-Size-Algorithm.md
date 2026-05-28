# Packet Size Algorithm: Covert Channel and Exfiltration Detection

## The Security Problem

Data exfiltration and covert channel communication often produce distinctive packet size patterns that are invisible to connection-based analysis. A covert channel sending fixed-size messages generates packets with identical lengths. A fragmentation attack produces highly variable packet sizes. An exfiltration tool may send unusually large packets to maximize data throughput. Conversely, command-and-control heartbeat packets may be unusually small.

These patterns are not detectable by port-based or flag-based analysis because the anomalies exist in the payload dimension, not the connection metadata. The UnusualPacketSizeDetector performs two-phase analysis — per-packet threshold checks grouped by source-destination pairs, followed by aggregate statistical analysis grouped by full connection tuples — to identify these patterns.

---

## Implementation Overview

```
┌──────────────┐     ┌─────────────────┐     ┌──────────────────┐     ┌────────────────┐
│  Guard check │────▶│  Iterate events │────▶│  Parse Length    │────▶│  Classify +    │
│  Enabled?    │     │  + cancellation │     │  from LinuxSpec  │     │  group         │
└──────────────┘     └─────────────────┘     └──────────────────┘     └────────────────┘
                                                                              │
                                                       ┌──────────────────────┤
                                                       │                      │
                                                       ▼                      ▼
                                              ┌──────────────┐     ┌──────────────────┐
                                              │ Size > largeThreshold │     │ 0 < Size < smallThreshold │
                                              │ → Medium     │     │ → Low           │
                                              │ (exfil/DoS)  │     │ (covert channel)│
                                              │ grouped by   │     │ grouped by      │
                                              │ (Src,Dst)    │     │ (Src,Dst)       │
                                              └──────────────┘     └──────────────────┘
                                                       │
                                                       ▼
                                              ┌──────────────────┐
                                              │ Aggregate phase  │
                                              │ per (Src,Dst,    │
                                              │  Port,Proto)     │
                                              │ (≥ minForAnalysis packets) │
                                              └────────┬─────────┘
                                         ┌──────────────┤──────────────┐
                                         ▼                             ▼
                                ┌──────────────┐            ┌──────────────────┐
                                │ Consistency  │            │ Variance         │
                                │ ≥ consistencyPercent same │            │ σ > varianceRatio × μ │
                                │ & > 10 count │            │ & μ > 100        │
                                │ → Medium     │            │ → Low            │
                                │ (covert ch.) │            │ (fragmentation)  │
                                └──────────────┘            └──────────────────┘
```

---

### Step A — Guard Check

```csharp
if (!profile.EnableUnusualPacketSize || events.Count == 0)
    return DetectionResult.Empty;
```

Immediate exit if packet size detection is disabled or no events exist.

---

### Step B — Per-Event Classification and Grouping

```csharp
var sizeByTuple = new Dictionary<(string SrcIP, string DstIP, int DstPort, string Proto), List<UnifiedEvent>>();
var largeGroups = new Dictionary<(string SrcIP, string DstIP), List<(int Size, DateTime Timestamp)>>();
var smallGroups = new Dictionary<(string SrcIP, string DstIP), List<(int Size, DateTime Timestamp)>>();

foreach (var evt in events)
{
    cancellationToken.ThrowIfCancellationRequested();

    var lengthStr = evt.LinuxSpecific.GetValueOrDefault("Length", "");
    if (!int.TryParse(lengthStr, out var length))
        continue;
```

Three grouping dictionaries are created before the loop. Each event's `Length` value is parsed as an integer. Successfully parsed sizes are classified into the appropriate groups. Events without parseable lengths are silently skipped.

---

### Step C — Large Packet Check (> 3000 bytes), Grouped by (SrcIP, DstIP)

```csharp
if (length > largeThreshold)
{
    var key = (evt.SourceIP, evt.DestinationIP);
    if (!largeGroups.TryGetValue(key, out var list))
    {
        list = new List<(int, DateTime)>();
        largeGroups[key] = list;
    }
    list.Add((length, evt.Timestamp));
}
```

Packets exceeding the large threshold (default 3000 bytes — double the standard 1500-byte MTU) are grouped by `(SourceIP, DestinationIP)` pairs. After all events are processed, one Medium-severity finding is emitted per group:

```csharp
foreach (var kvp in largeGroups)
{
    findings.Add(new Core.Finding
    {
        Category = FindingCategories.UnusualPacketSize,
        Severity = Core.Severity.Medium,
        SourceHost = kvp.Key.SrcIP,
        Target = kvp.Key.DstIP,
        ...
        ShortDescription = $"{entries.Count} unusually large packet(s) detected",
        Details = $"{entries.Count} packet(s) from {kvp.Key.SrcIP} to {kvp.Key.DstIP} exceeded {largeThreshold} bytes ..."
    });
}
```

---

### Step D — Small Packet Check (> 0 and < 40 bytes), Grouped by (SrcIP, DstIP)

```csharp
if (length > 0 && length < smallThreshold)
{
    var key = (evt.SourceIP, evt.DestinationIP);
    if (!smallGroups.TryGetValue(key, out var list))
    {
        list = new List<(int, DateTime)>();
        smallGroups[key] = list;
    }
    list.Add((length, evt.Timestamp));
}
```

Packets between 1 and 39 bytes are grouped by `(SourceIP, DestinationIP)` pairs. The minimum TCP/IP header is 40 bytes (20 IP + 20 TCP), so anything smaller indicates a malformed or crafted packet. Zero-length packets are excluded because they may represent metadata-only log entries. After all events are processed, one Low-severity finding is emitted per group.

---

### Step E — Aggregate Analysis per Connection Tuple

```csharp
foreach (var kvp in sizeByTuple)
{
    var tupleEvents = kvp.Value;
    if (tupleEvents.Count < minForAnalysis)
        continue;

    var avgSize = packetSizes.Average();
    var variance = packetSizes.Select(s => (s - avgSize) * (s - avgSize)).Average();
    var stdDev = Math.Sqrt(variance);
```

The aggregate phase groups events by `(SrcIP, DstIP, DstPort, Proto)` tuples and requires more than `minForAnalysis` (default 10) packets per tuple to avoid statistical noise from small samples. Mean and standard deviation are computed for the full packet size distribution within each tuple.

---

### Step F — Consistency Check (Covert Channel)

```csharp
var sourceHost = kvp.Key.SrcIP;
var target = $"{kvp.Key.DstIP}:{kvp.Key.DstPort}";

if (consistencyPct >= consistencyPercent && mostCommonSize.Count() >= minConsistentCount)
{
    findings.Add(new Core.Finding
    {
        Category = FindingCategories.UnusualPacketSize,
        Severity = Core.Severity.Medium,
        SourceHost = sourceHost,
        Target = target,
        ...
        Details = $"{consistencyPct:F1}% of packets from {sourceHost} to {target} have the same size ({mostCommonSize.Key} bytes). ..."
    });
}
```

If more than `consistencyPercent` (default 70%) of packets share the exact same size, and more than `minConsistentCount` (default 10) packets exhibit that size, a Medium-severity finding is emitted. The `SourceHost` is the actual source IP and `Target` is `DstIP:DstPort` — not generic placeholders — so analysts can trace the exact flow. Fixed-size packets are a hallmark of covert channels — legitimate traffic typically shows natural size variation. The dual threshold (percentage + absolute count) prevents false positives from small, homogeneous traffic bursts.

---

### Step G — Variance Check (Fragmentation)

```csharp
if (stdDev > avgSize * varianceRatio && avgSize > minAvgForVariance)
{
    findings.Add(new Core.Finding
    {
        Category = FindingCategories.UnusualPacketSize,
        Severity = Core.Severity.Low,
        SourceHost = sourceHost,
        Target = target,
        ...
        Details = $"Packet sizes from {sourceHost} to {target} show high variance (avg: {avgSize:F0} bytes, std dev: {stdDev:F0} bytes). ..."
    });
}
```

If the standard deviation exceeds `varianceRatio` (default 0.5) times the mean, and the mean is above `minAvgForVariance` (default 100 bytes), a Low-severity finding is emitted. The `SourceHost` and `Target` use the same actual IP and `DstIP:DstPort` values as the consistency check. High variance relative to the mean indicates bimodal or fragmented traffic — some full-size packets mixed with many small fragments. The `avgSize > minAvgForVariance` guard prevents triggering on low-mean traffic where proportional variance is naturally high.

---

## Complexity And Behavior

| Aspect | Behavior | Rationale |
|---|---|---|
| Time complexity | O(N) | Single pass per-packet, plus per-group aggregate analysis |
| Space complexity | O(N) | Stores all events in grouping dictionaries for aggregate statistics |
| Per-packet thresholds | > 3000 (Medium), < 40 (Low) | Based on standard MTU and minimum header sizes |
| Threshold grouping | By (SrcIP, DstIP) pairs | One finding per source-destination pair, not per packet |
| Aggregate grouping | By (SrcIP, DstIP, DstPort, Proto) tuples | Statistical analysis per unique connection |
| Aggregate gate | ≥ minForAnalysis packets required | Avoids noisy statistics from small samples |
| Consistency threshold | ≥ consistencyPercent same size AND ≥ minConsistentCount packets | Dual threshold prevents false positives |
| Variance threshold | σ > varianceRatio × mean AND mean > minAvgForVariance | Proportional variance with absolute minimum |
| Cancellation | Checked per event | Allows graceful shutdown on large inputs |

---

## Implementation Evidence

- [UnusualPacketSizeDetector.cs](../../../../../VulcansTrace.Linux.Engine/Detectors/UnusualPacketSizeDetector.cs) — detector implementation
- [UnusualPacketSizeDetectorTests.cs](../../../../../VulcansTrace.Linux.Tests/Detectors/Linux/UnusualPacketSizeDetectorTests.cs) — test suite

---

## Security Takeaways

1. The two-phase design separates clear-cut per-packet anomalies (size > largeThreshold or < smallThreshold) from statistical patterns that only emerge in aggregate
2. Per-packet threshold findings are grouped by `(SrcIP, DstIP)` pairs — one finding per pair, not one per packet — keeping alerts manageable during sustained exfiltration or DoS attacks
3. The 10-packet gate for aggregate analysis prevents false positives from small traffic bursts — statistical significance requires sample size
4. The consistency check (≥ consistencyPercent same size) targets covert channels that use fixed-size packets for structured data exfiltration or C2 communication
5. The variance check (σ > varianceRatio × mean) targets fragmentation attacks and mixed-traffic anomalies, but at Low severity because high variance has benign causes
6. Both aggregate checks use actual `SourceIP` and `DstIP:DstPort` as `SourceHost` and `Target`, enabling analysts to trace findings to specific flows
