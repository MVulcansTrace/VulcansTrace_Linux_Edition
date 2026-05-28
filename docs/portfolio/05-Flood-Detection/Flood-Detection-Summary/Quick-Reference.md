# Flood Detection — Quick Reference

## Algorithm Steps

1. **Guard** — return empty if `EnableFlood` is false or events list is empty
2. **Group by source IP** — `GroupBy(e => e.SourceIP)`
3. **Sort each group** — order by timestamp ascending
4. **Slide two-pointer window** — advance `end`, shrink `start` when window exceeds `FloodWindowSeconds`
5. **Count events** — `windowCount = end - start + 1`
6. **Threshold check** — create or extend a finding when `windowCount >= FloodMinEvents`; track peak event count during the burst
7. **Finding finalization** — when event count drops below threshold, close the active finding; the scan continues and may create new findings for later bursts

---

## Configuration Parameters

| Parameter | Type | Low Profile | Medium Profile | High Profile |
|---|---|---|---|---|
| `EnableFlood` | bool | true | true | true |
| `FloodWindowSeconds` | int | 60 | 60 | 60 |
| `FloodMinEvents` | int | 400 | 200 | 100 |

---

## Downstream Pipeline

```
Raw iptables log
      |
      v
  LogNormalizer (format detection + parsing)
      |
      v
  UnifiedEvent[] (validated, immutable)
      |
      v
  FloodDetector.Detect()
      |
      v
  Finding { Category="Flood", Severity=High }
      |
      v
  Risk Escalation Engine
      |
      v
  Severity Filtering (MinSeverityToShow; Flood findings always pass)
      |
      v
  Evidence Bundle (ZIP output)
```

---

## Finding Structure

| Field | Value |
|---|---|
| `Category` | `"Flood"` |
| `Severity` | `High` |
| `SourceHost` | Attacker IP |
| `Target` | `"multiple hosts/ports"` |
| `TimeRangeStart` | Window start timestamp |
| `TimeRangeEnd` | Window end timestamp |
| `ShortDescription` | `"Flood detected from {IP}"` |
| `Details` | `"Detected {N} events within {W} seconds."` |

---

## Complexity

| Dimension | Value |
|---|---|
| Time (per source) | O(n log n) — sort dominates |
| Space (per source) | O(n) — ordered event list |
| Overall (k sources) | O(N log n_max) where n_max is the largest source group |

---

## MITRE ATT&CK Mapping

| Technique | ID | Tactic | Detection |
|---|---|---|---|
| Network Denial of Service | T1498 | Impact (TA0040) | Primary — high-volume connection floods |
| Endpoint Denial of Service | T1499 | Impact (TA0040) | Indirect — resource exhaustion via connection volume |
| Impact (Parent Tactic) | TA0040 | — | All volumetric attack patterns | 

---

## Evasion Summary

| Evasion Technique | Effectiveness | Mitigation |
|---|---|---|
| Distributed flood (DDoS) | High | Aggregate across source IP ranges |
| Slow-rate flood | Full | No duration minimum; may miss extended attacks |
| Pulsed attacks (on/off) | Medium | Window alignment may miss pause boundaries |
| Legitimate traffic spoofing | Medium | Cross-reference with service baselines |

---

## File References

| File | Path | Role |
|---|---|---|
| FloodDetector.cs | `VulcansTrace.Linux.Engine/Detectors/` | Detection logic |
| AnalysisProfile.cs | `VulcansTrace.Linux.Engine/` | Threshold configuration |
| FloodDetectorTests.cs | `VulcansTrace.Linux.Tests/Detectors/Baseline/` | Detector behavior coverage |
