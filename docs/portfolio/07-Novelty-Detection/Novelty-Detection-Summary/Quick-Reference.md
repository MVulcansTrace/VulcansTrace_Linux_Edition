# Novelty Detection — Quick Reference

## Algorithm Steps

1. **Guard** — return empty if `EnableNovelty` is false or events list is empty
2. **Filter** — keep events where destination IP is external
3. **Early exit** — return empty if no external-destination events exist
4. **Pass 1: Build frequency** — group by (DestIP, DestPort), count occurrences, store in dictionary
5. **Pass 2: Extract singletons** — for each external event, check if its (DestIP, DestPort) count ≤ `NoveltyMaxGlobalOccurrences` (default 1); group singletons by source IP
6. **Emit finding** — one low-severity finding per source IP, with comma-separated target list (up to 5 + "...")

---

## Configuration Parameters

| Parameter | Type | Low Profile | Medium Profile | High Profile |
|---|---|---|---|---|
| `EnableNovelty` | bool | false | true | true |
| `NoveltyMaxGlobalOccurrences` | int | 1 | 1 | 1 |

Note: `NoveltyMaxGlobalOccurrences` controls the rarity threshold. A destination is "novel" if its global occurrence count is ≤ this value. Default is 1 (strict singletons); increasing to 2–3 catches near-singletons at the cost of more noise.

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
  NoveltyDetector.Detect()
      |
      v
  Finding[] { Category="Novelty", Severity=Low }
      |
      v
  Risk Escalation Engine
      |
      v
  Evidence Bundle (ZIP output)
```

---

## Finding Structure

| Field | Value |
|---|---|
| `Category` | `FindingCategories.Novelty` |
| `Severity` | `Low` |
| `SourceHost` | Source IP |
| `Target` | Comma-separated list of up to 5 `"IP:Port"` entries (+ `"..."` if more) |
| `TimeRangeStart` | `minTime` across source's singletons |
| `TimeRangeEnd` | `maxTime` across source's singletons |
| `ShortDescription` | `"{Count} novel destination(s) from {SourceIP}"` |
| `Details` | `"Source {SourceIP} contacted {Count} external destination(s) exactly once. This may indicate reconnaissance or testing of exfiltration channels."` |

---

## Complexity

| Dimension | Value |
|---|---|
| Time | O(n) — two passes, each O(n), with O(1) dictionary operations |
| Space | O(n) — frequency dictionary stores one entry per unique (IP, Port) pair |
| Passes | 2 — mandatory for correct singleton identification |

---

## MITRE ATT&CK Mapping

| Technique | ID | Tactic | Detection |
|---|---|---|---|
| Network Service Discovery | T1046 | Discovery (TA0007) | Primary — single probes to services |
| Remote System Discovery | T1018 | Discovery (TA0007) | Primary — single connections to new hosts |
| Discovery (Parent Tactic) | TA0007 | — | All one-time reconnaissance patterns |

---

## Evasion Summary

| Evasion Technique | Effectiveness | Mitigation |
|---|---|---|
| Double-tap (connect twice) | Full | Reduce threshold from count==1 to count<=N |
| Slow reconnaissance | None | Singleton detection is time-independent |
| Distributed scanning | Low | Each source's singletons are still detected |
| Burst scanning | None | Frequency-based, not volume-based |

---

## File References

| File | Path | Lines |
|---|---|---|
| NoveltyDetector.cs | `VulcansTrace.Linux.Engine/Detectors/` | 83 |
| NoveltyDetectorTests.cs | `VulcansTrace.Linux.Tests/Detectors/Baseline/` | 74 |
