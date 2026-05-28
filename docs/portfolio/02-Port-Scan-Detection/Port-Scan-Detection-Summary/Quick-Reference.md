# Quick Reference: Port Scan Detection

## Algorithm Steps

1. **Guard** — If `EnablePortScan` is false or the event list is empty, return immediately with no findings
2. **Group by source** — Group all events by `SourceIP`
3. **Order chronologically** — Sort each source group by `Timestamp`
4. **Truncate** — If `PortScanMaxEntriesPerSource` is set and exceeded, take only the latest N events and emit a warning
5. **Pre-window gate** — Count distinct destination ports for the source; if below `PortScanMinPorts`, skip this source
6. **Sliding window** — Move start/end pointers across ordered events using `PortScanWindowMinutes`
7. **Count per window** — For each active window, count distinct destination ports
8. **Emit finding** — If count >= `PortScanMinPorts`, create a Medium-severity `PortScan` finding with time range and target count

---

## Configuration Parameters

| Parameter | Type | Description | Low | Medium | High |
|---|---|---|---|---|---|
| `EnablePortScan` | `bool` | Enable/disable port scan detection | true | true | true |
| `PortScanMinPorts` | `int` | Minimum distinct destination ports per window to trigger | 30 | 15 | 8 |
| `PortScanWindowMinutes` | `int` | Time window size in minutes | 5 | 5 | 5 |
| `PortScanMaxEntriesPerSource` | `int?` | Max events analyzed per source IP (null = unlimited) | null | null | null |

---

## Downstream Pipeline

```
┌─────────────┐    ┌──────────────────┐    ┌──────────────────┐    ┌────────────────┐
│  Log         │    │  UnifiedEvent     │    │  PortScan         │    │  RiskEscalator  │
│  Normalizer  │───▶│  Stream           │───▶│  Detector         │───▶│  (correlation)  │
└─────────────┘    └──────────────────┘    └──────────────────┘    └────────────────┘
                                                    │
                                                    ▼
                                            ┌──────────────────┐
                                            │  Finding:         │
                                            │  Category=PortScan│
                                            │  Severity=Medium  │
                                            └──────────────────┘
```

> **Escalation:** When the `RiskEscalator` detects time-correlated `PortScan` and `FlagAnomaly` findings on the same source host, it escalates those participating findings to Critical severity.

---

## Finding Structure

| Field | Value |
|---|---|
| `Category` | `"PortScan"` |
| `Severity` | `Medium` |
| `SourceHost` | The scanning source IP |
| `Target` | `"multiple ports"` |
| `TimeRangeStart` | Earliest timestamp in the matching window |
| `TimeRangeEnd` | Latest timestamp in the matching window |
| `ShortDescription` | `"Port scan detected from {sourceIP}"` |
| `Details` | `"Detected {count} distinct destination ports within {window} minutes."` |

---

## Complexity

| Dimension | Complexity | Notes |
|---|---|---|
| Time | O(N log N) per source | Dominated by the `OrderBy` on timestamp |
| Space | O(N) per source | Stores ordered event list per source group |
| Pre-window gate | O(N) | Single pass to count distinct destination ports |
| Sliding window | O(N) | Single pass with start/end pointers and port counts |

---

## MITRE ATT&CK

| Technique ID | Name | Relevance |
|---|---|---|
| T1046 | Network Service Discovery | Primary technique — attacker probes ports to map running services |
| T1595 | Active Scanning | Pre-attack phase — external reconnaissance of target network |
| T1595.001 | Active Scanning: Scanning IP Blocks | Related — port scanning often precedes block scanning |
| T1595.002 | Active Scanning: Vulnerability Scanning | Indirectly addressed — vulnerability scanners produce the same traffic pattern as port scans |

---

## Evasion Summary

| Evasion Technique | Effect on Detection | Mitigation |
|---|---|---|
| Slow scanning (distributed over hours) | Events spread beyond the sliding window, count may not meet threshold | Use a more sensitive profile or add cumulative detection |
| Distributed scanning (multiple source IPs) | Each source evaluated independently | Correlate with other detectors or threat intelligence |
| Decoy traffic injection | Inflates event count but not distinct destination ports | Minimal — distinct counting is inherently resistant |
| Port scan below threshold | Evades detection entirely | Lower threshold via High intensity profile |
| No protocol differentiation | TCP, UDP, and ICMP scans counted toward the same threshold | Add protocol-aware thresholds (future improvement) |
| Spoofed source IP | Finding points to wrong host | Correlate with MAC address and interface data |

---

## File References

| File | Role |
|---|---|
| [PortScanDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/PortScanDetector.cs) | Detector implementation |
| [AnalysisProfile.cs](../../../../VulcansTrace.Linux.Engine/AnalysisProfile.cs) | Threshold configuration record |
| [AnalysisProfileProvider.cs](../../../../VulcansTrace.Linux.Engine/Configuration/AnalysisProfileProvider.cs) | Intensity-based presets |
| [PortScanDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/Baseline/PortScanDetectorTests.cs) | Test suite |
| [RiskEscalator.cs](../../../../VulcansTrace.Linux.Engine/RiskEscalator.cs) | Correlated severity escalation |

---

## Security Takeaways

1. Distinct-port counting in time windows provides a robust signal against repeated single-port traffic and multi-port sweeps
2. Profile-based thresholds let operators tune sensitivity without modifying detector code
3. The pre-window gate avoids wasted computation on low-activity sources
4. Truncation with warnings maintains transparency when data volume forces approximations
5. The detector's findings are consumed downstream by the `RiskEscalator` for correlated threat assessment
