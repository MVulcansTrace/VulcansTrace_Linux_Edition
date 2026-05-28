# Quick Reference: Linux Deep Inspection

## Algorithm Steps — Flag Anomaly Detector

1. **Guard** — If `EnableFlagAnomaly` is false or events are empty, return no findings
2. **Iterate events** — Loop over all events with cooperative cancellation
3. **Protocol filter** — Skip non-TCP events
4. **Extract flags** — Read `LinuxSpecific["Flags"]` and convert to uppercase
5. **XMAS check** — If flags are non-empty and contain `FIN`, `PSH`, and `URG`, aggregate event as `XMAS-scan`
6. **FIN-without-SYN check** — Else-if flags contain `FIN` but not `SYN`, aggregate event as `FIN-without-SYN`
7. **Emit findings** — After all events, emit one Medium-severity finding per `(SourceIP, AnomalyType)` group with up to 5 sample targets

---

## Algorithm Steps — MAC Spoofing Detector

1. **Guard** — If `EnableMacSpoofing` is false or events are empty, return no findings
2. **Group by IP** — Group all events by `SourceIP`
3. **Normalize MACs** — Filter non-empty MACs, normalize via `FirewallLogRegex.NormalizeMacField`, filter again, order by timestamp
4. **Sliding window** — Two-pointer scan within configurable time window (`MacSpoofingWindowMinutes`, default 5), tracking the window with maximum distinct MACs
5. **Multi-MAC check** — If best window has > 1 distinct MAC, emit High-severity finding with MAC list and window time range

---

## Algorithm Steps — Kernel Module Detector

1. **Guard** — If `EnableKernelModule` is false or events are empty, return no findings
2. **Iterate events** — Loop over all events, checking `RawLine` for signatures
3. **Signature matching** — `IsWholeToken` for: conntrack/CT → Connection Tracking, limit/rate → Rate Limiting, layer7/l7 → Layer 7 Filtering, quota/hashlimit → Quota/Bandwidth Limiting; `:` in IP → IPv6 Support
4. **Timestamp collection** — Detected module names and their timestamps are collected in a `Dictionary<string, List<DateTime>>`
5. **Emit findings** — One Info-severity finding per detected module, with time range from the module's own timestamps

---

## Algorithm Steps — Interface Hopping Detector

1. **Guard** — If `EnableInterfaceHopping` is false or events are empty, return no findings
2. **Group by IP** — Group all events by `SourceIP`
3. **Collect interfaces** — For each IP group, filter non-empty `LinuxSpecific["InterfaceIn"]` values, order by timestamp
4. **Sliding window** — Two-pointer scan within configurable time window (`InterfaceHoppingWindowMinutes`, default 5), tracking the window with maximum distinct interfaces
5. **Multi-interface check** — If best window has > 1 distinct interface, emit Medium-severity finding with interface list and window time range

---

## Algorithm Steps — Unusual Packet Size Detector

1. **Guard** — If `EnableUnusualPacketSize` is false or events are empty, return no findings
2. **Per-event classification** — Parse `LinuxSpecific["Length"]` as integer, classify into grouped dictionaries during a single pass
3. **Large packet check** — Size > `PacketSizeLargeThreshold` (Low=4000, Med=3000, High=2000), grouped by `(SrcIP, DstIP)` → one Medium-severity finding per pair
4. **Small packet check** — Size > 0 and < `PacketSizeSmallThreshold` (Low=20, Med=40, High=60), grouped by `(SrcIP, DstIP)` → one Low-severity finding per pair
5. **Aggregate analysis** per `(SrcIP, DstIP, DstPort, Proto)` tuple (requires ≥ `PacketSizeMinForAnalysis` packets: Low=15, Med=10, High=5):
   - **Consistency check** — If ≥ `PacketSizeConsistencyPercent` of packets share the same size with ≥ `PacketSizeMinConsistentCount` packets at that size (Low=80%/15, Med=70%/10, High=60%/5) → Medium (covert channel)
   - **Variance check** — If std dev > `PacketSizeVarianceRatio` × mean and mean > `PacketSizeMinAvgForVariance` (Low=0.6/150, Med=0.5/100, High=0.4/80) → Low (fragmentation)

---

## Configuration Parameters

| Parameter | Type | Description |
|---|---|---|
| `EnableFlagAnomaly` | `bool` | Enable/disable TCP flag anomaly detection |
| `EnableMacSpoofing` | `bool` | Enable/disable MAC spoofing detection |
| `MacSpoofingWindowMinutes` | `int` | Sliding window size for MAC diversity analysis (default 5) |
| `EnableKernelModule` | `bool` | Enable/disable kernel module posture assessment |
| `EnableInterfaceHopping` | `bool` | Enable/disable interface hopping detection |
| `InterfaceHoppingWindowMinutes` | `int` | Sliding window size for interface diversity analysis (default 5) |
| `EnableUnusualPacketSize` | `bool` | Enable/disable unusual packet size detection |
| `PacketSizeLargeThreshold` | `int` | Threshold for large packet detection (default 3000) |
| `PacketSizeSmallThreshold` | `int` | Threshold for small packet detection (default 40) |
| `PacketSizeMinForAnalysis` | `int` | Minimum packets per tuple for aggregate analysis (default 10) |
| `PacketSizeConsistencyPercent` | `int` | Consistency percentage threshold (default 70) |
| `PacketSizeMinConsistentCount` | `int` | Minimum packets at same size for consistency (default 10) |
| `PacketSizeVarianceRatio` | `double` | Std dev / mean ratio for variance check (default 0.5) |
| `PacketSizeMinAvgForVariance` | `int` | Minimum average size for variance check (default 100) |

---

## Downstream Pipeline

```
┌─────────────┐    ┌──────────────────┐    ┌───────────────────────┐    ┌────────────────┐
│  Log         │    │  UnifiedEvent     │    │  Linux Deep Inspection│    │  RiskEscalator  │
│  Normalizer  │───▶│  + LinuxSpecific  │───▶│  Detectors (5)        │───▶│  (correlation)  │
└─────────────┘    └──────────────────┘    └───────────────────────┘    └────────────────┘
                                                │
                                    ┌───────────┼───────────┬──────────────┬──────────────┐
                                    ▼           ▼           ▼              ▼              ▼
                              ┌──────────┐┌──────────┐┌──────────┐  ┌──────────────┐┌──────────────┐
                              │Flag      ││MAC       ││Kernel    │  │Interface     ││Packet Size   │
                              │Anomaly   ││Spoofing  ││Module    │  │Hopping       ││Anomaly       │
                              │Medium    ││High      ││Info      │  │Medium        ││Low–Medium    │
                              └──────────┘└──────────┘└──────────┘  └──────────────┘└──────────────┘
```

---

## Finding Structures

| Detector | Category | Default Severity | Target | Key Details |
|---|---|---|---|---|
| Flag Anomaly | `FlagAnomaly` | Medium | Up to 5 `DestIP:DestPort` targets | Flag combination, scan type, target count |
| MAC Spoofing | `MacSpoofing` | High | `multiple MAC addresses` | MAC count, address list, window minutes |
| Kernel Module | `KernelModule` | Info | Module name | Module capabilities, timestamp range |
| Interface Hopping | `InterfaceHopping` | Medium | `N network interfaces` | Interface list, window minutes |
| Packet Size (large) | `UnusualPacketSize` | Medium | `DstIP` | Packet count, size range |
| Packet Size (small) | `UnusualPacketSize` | Low | `DstIP` | Packet count, threshold |
| Packet Size (consistency) | `UnusualPacketSize` | Medium | `DstIP:DstPort` | Consistency percentage, common size |
| Packet Size (variance) | `UnusualPacketSize` | Low | `DstIP:DstPort` | Average and std dev |

---

## Complexity

| Detector | Time | Space | Notes |
|---|---|---|---|
| Flag Anomaly | O(N) | O(G) | G = groups; single pass with aggregation |
| MAC Spoofing | O(N log N) | O(M) | M = distinct MACs; GroupBy + OrderBy + sliding window |
| Kernel Module | O(N × S) | O(K) | S = signatures, K = detected modules; per-event scan |
| Interface Hopping | O(N log N) | O(I) | I = distinct interfaces; GroupBy + OrderBy + sliding window |
| Packet Size | O(N) | O(N) | Stores events in grouping dictionaries for aggregate stats |

---

## MITRE ATT&CK

| Detector | Technique ID | Name | Relevance |
|---|---|---|---|
| Flag Anomaly | T1046 | Network Service Discovery | FIN/XMAS scans probe port state |
| Flag Anomaly | T1595 | Active Scanning | Stealth scan techniques for reconnaissance |
| MAC Spoofing | T1200 | Hardware Additions | MAC manipulation for network masquerading |
| MAC Spoofing | T1595.002 | Vulnerability Scanning | L2 reconnaissance preceding exploitation |
| Kernel Module | T1562.001 | Impair Defenses | Identifies defensive capabilities that could be targeted |
| Interface Hopping | T1046 | Network Service Discovery | Multi-interface probing for service mapping |
| Interface Hopping | T1595 | Active Scanning | Interface enumeration during reconnaissance |
| Packet Size | T1048 | Exfiltration Over Alternative Protocol | Unusual sizes indicate non-standard data movement |
| Packet Size | T1571 | Non-Standard Port | Covert channels use fixed-size or anomalous packets |

---

## Evasion Summary

| Evasion Technique | Affected Detector | Effect | Mitigation |
|---|---|---|---|
| Fragmented flags across packets | Flag Anomaly | May evade if flags are split | Correlate with port scan detector |
| Legitimate MAC changes (VM migration) | MAC Spoofing | False positive | Time-window filtering, VM allowlists |
| Obfuscated module names | Kernel Module | Missed detection | Expand signature set |
| Slow interface switching (> window) | Interface Hopping | Evades sliding-window check | Configurable window or cumulative detection |
| Packets at threshold boundaries | Packet Size | Slightly large/small packets evade | Adjust thresholds per environment |

---

## File References

| File | Role |
|---|---|
| [FlagAnomalyDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/FlagAnomalyDetector.cs) | Flag anomaly detector |
| [MacSpoofingDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/MacSpoofingDetector.cs) | MAC spoofing detector |
| [KernelModuleDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/KernelModuleDetector.cs) | Kernel module detector |
| [InterfaceHoppingDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/InterfaceHoppingDetector.cs) | Interface hopping detector |
| [UnusualPacketSizeDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/UnusualPacketSizeDetector.cs) | Packet size detector |
| [RiskEscalator.cs](../../../../VulcansTrace.Linux.Engine/RiskEscalator.cs) | Correlated severity escalation |
| [FlagAnomalyDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/Linux/FlagAnomalyDetectorTests.cs) | Flag anomaly tests |
| [MacSpoofingDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/Linux/MacSpoofingDetectorTests.cs) | MAC spoofing tests |
| [KernelModuleDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/Linux/KernelModuleDetectorTests.cs) | Kernel module tests |
| [InterfaceHoppingDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/Linux/InterfaceHoppingDetectorTests.cs) | Interface hopping tests |
| [UnusualPacketSizeDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/Linux/UnusualPacketSizeDetectorTests.cs) | Packet size tests |

---

## Security Takeaways

1. Five detectors cover five distinct attack dimensions — no single detector tries to do everything
2. Each detector uses the appropriate severity level — Info for posture, Low for low-confidence anomalies, Medium for likely attacks, High for confirmed integrity violations
3. The `RiskEscalator` provides the only cross-detector correlation, keeping individual detectors simple and testable
4. Guard clauses ensure disabled detectors consume zero resources — useful for tuning detection scope per deployment
5. Cooperative cancellation in all detectors prevents runaway processing on large log files
