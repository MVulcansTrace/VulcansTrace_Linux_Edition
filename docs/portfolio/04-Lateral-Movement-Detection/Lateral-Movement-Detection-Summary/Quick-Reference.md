# Lateral Movement Detection — Quick Reference

## Algorithm Steps

1. **Guard** — return empty if `EnableLateralMovement` is false or events list is empty
2. **Build admin port set** — `HashSet<int>` from `profile.AdminPorts` (profile default [445, 3389, 22])
3. **Filter** — keep events where source is internal, destination is internal, and dest port is in admin set
4. **Group by source IP** — `GroupBy(e => e.SourceIP)`
5. **Sort each group** — order by timestamp ascending
6. **Slide two-pointer window** — advance `end`, shrink `start` when window exceeds `LateralWindowMinutes`
7. **Count distinct destinations** — `Dictionary<string, int>` tracks host counts incrementally within the window
8. **Threshold check** — create or extend a finding when distinct hosts >= `LateralMinHosts`; track peak host count during the burst
9. **Finding finalization** — when distinct hosts drops below threshold, close the active finding; the scan continues and may create new findings for later bursts

---

## Configuration Parameters

| Parameter | Type | Low Profile | Medium Profile | High Profile |
|---|---|---|---|---|
| `EnableLateralMovement` | bool | true | true | true |
| `AdminPorts` | IReadOnlyList\<int\> | [445, 3389, 22] | [445, 3389, 22] | [445, 3389, 22] |
| `LateralWindowMinutes` | int | 10 | 10 | 10 |
| `LateralMinHosts` | int | 6 | 4 | 3 |

---

## Downstream Pipeline

```
Raw iptables log
      |
      v
  LogNormalizer (format detection + parsing)
      |
      v
  IReadOnlyList<UnifiedEvent> (validated, immutable)
      |
      v
  LateralMovementDetector.Detect()
      |
      v
  Finding { Category="LateralMovement", Severity=High }
      |
      v
  RiskEscalator
      |
      v
  Evidence Bundle (ZIP output)
```

---

## Finding Structure

| Field | Value |
|---|---|
| `Category` | `"LateralMovement"` |
| `Severity` | `High` |
| `SourceHost` | Attacker internal IP |
| `Target` | `"multiple internal hosts"` |
| `TimeRangeStart` | Window start timestamp |
| `TimeRangeEnd` | Window end timestamp |
| `ShortDescription` | `"Lateral movement from {IP}"` |
| `Details` | `"Contacted {N} internal hosts on admin ports."` |

---

## Complexity

| Dimension | Value |
|---|---|
| Time (per source) | O(n log n) amortized — sort dominates; window scan is O(n) via Dictionary counting |
| Space (per source) | O(n) — ordered event list + host dictionary |
| Overall (k sources) | O(N · log(n_max)) where n_max is the largest source group |

---

## MITRE ATT&CK Mapping

| Technique | ID | Tactic | Detection |
|---|---|---|---|
| Remote Services | T1021 | Lateral Movement (TA0008) | Primary — SMB/RDP/SSH connections |
| Windows Management Instrumentation | T1047 | Execution (TA0002) | Indirect — WMI uses ports not in default admin ports |
| Command and Scripting Interpreter | T1059 | Execution (TA0002) | Indirect — SSH port 22 activity |

---

## Evasion Summary

| Evasion Technique | Effectiveness | Mitigation |
|---|---|---|
| Slow lateral movement (> window) | High | Extend window or implement adaptive thresholds |
| Non-admin port pivoting | Full | Add additional monitored ports via profile |
| Encrypted tunnels on admin ports | Low | Connection frequency still visible |
| IP rotation via DHCP | Medium | Correlate with MAC address or hostname |

---

## File References

| File | Path | Lines |
|---|---|---|
| LateralMovementDetector.cs | `VulcansTrace.Linux.Engine/Detectors/` | 120 |
| IpClassification.cs | `VulcansTrace.Linux.Engine/Net/` | 157 |
| AnalysisProfile.cs | `VulcansTrace.Linux.Engine/` | 195 |
| LateralMovementDetectorTests.cs | `VulcansTrace.Linux.Tests/Detectors/Baseline/` | 687 |
