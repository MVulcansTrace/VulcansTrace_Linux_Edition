# Quick Reference

---

## Detection Algorithm (9 Steps)

Step A: Toggle Gate -- skip if EnableC2Detection is false or entries are empty
Step B: Tolerance Guard -- skip if C2ToleranceSeconds <= 0
Step C: Group by {SourceIP}-{DestIP}:{DestPort}-{Protocol} -- isolate each channel (source port excluded)
Step D: Chronological sort + compute consecutive time deltas
Step E: Cluster deltas using greedy sliding window -- sort deltas, then group consecutive values within `tolerance * 2` span; group interval is the average of its members
Step F: Filter buckets with count >= C2MinOccurrences
Step G: Skip intervals outside [C2MinIntervalSeconds, C2MaxIntervalSeconds]
Step H: Reconstruct pattern events from matching deltas
Step I: Emit Finding if patternEvents.Count >= C2MinPatternEvents

---

## Configuration Parameters

| Parameter | Low | Medium | High |
|-----------|-----|--------|------|
| EnableC2Detection | false | true | true |
| C2ToleranceSeconds | 10.0 | 5.0 | 8.0 |
| C2MinIntervalSeconds | 120 | 60 | 30 |
| C2MaxIntervalSeconds | 3600 | 1800 | 1800 |
| C2MinOccurrences | 5 | 3 | 2 |
| C2MinPatternEvents | 10 | 6 | 4 |
| C2MinGroupSize | 4 | 3 | 3 |

> **Note:** Although Low profile has threshold values defined, `EnableC2Detection = false` means the detector never runs at Low intensity. The Low values exist for completeness but have no operational effect.

---

## Downstream Pipeline

```text
C2ChannelDetector (High) -> MinSeverityToShow filter
```

C2 channel findings start at High severity. No cross-detector escalation is applied. At Low profile (where the detector is disabled), findings never appear. At Medium profile, High-severity findings pass the `MinSeverityToShow = Medium` gate. At High profile, they pass the `MinSeverityToShow = Info` gate.

---

## Finding Structure

| Field | Value |
|-------|-------|
| Category | "C2Channel" |
| Severity | High |
| SourceHost | Source IP |
| Target | "{DestinationIP}:{DestinationPort}" |
| TimeRangeStart | First pattern event timestamp |
| TimeRangeEnd | Last pattern event timestamp |
| ShortDescription | "Potential C2 channel detected: {connectionKey}" |
| Details | "Detected {count} events with approximately {interval}s intervals (tolerance: +/-{tolerance}s). This pattern suggests periodic communication that may indicate a C2 channel." |

---

## Complexity

| Metric | Value |
|--------|-------|
| Time (worst) | O(n log n) |
| Time (average) | O(n log(n/t)) |
| Space | O(n) |

---

## MITRE ATT&CK

| Scenario | Technique |
|----------|-----------|
| Analyst-mapped C2 over Application Layer Protocol | T1071 |
| Analyst-mapped C2 over Non-Application Layer Protocol | T1095 |
| Analyst-mapped Encrypted Channel | T1573 |
| Command and Control tactic | TA0011 |

> **Note:** These are analyst-applied mappings based on surrounding evidence. The detector itself analyzes timing on `{SourceIP}-{DestIP}:{DestPort}-{Protocol}` groups and does not classify protocol or encryption semantics directly. The full mapping discussion is in the In-Depth MITRE-ATTACK-Mapping file.

---

## Key Formulas

```
Group Span = tolerance * 2
Group Formation = consecutive sorted deltas where max - min <= groupSpan
Group Interval = average of grouped deltas
```

---

## Evasion Summary

| Technique | Status | Countermeasure |
|-----------|--------|---------------|
| Jitter beyond tolerance | Depends on profile | Higher tolerance profiles, or Beaconing detector with std dev |
| Domain flux | Missed | Cross-tuple correlation by source IP + timing |
| DNS tunneling | Missed | DNS-specific analysis layer |
| No payload inspection | Missed | Deep packet inspection integration |
| Variable-length intervals | Partial | Beaconing detector as complementary approach |

---

## File References

| File | Purpose |
|------|---------|
| C2ChannelDetector.cs | Detector implementation |
| IDetector.cs | Strategy interface |
| Finding.cs | Output model |
| AnalysisProfile.cs | Configuration (6 thresholds + 1 toggle) |
| AnalysisProfileProvider.cs | Low/Medium/High presets |
| C2ChannelDetectorTests.cs | Test coverage (14 methods) |

---

## Security Takeaways

1. **C2 channels are a post-compromise signal** -- detecting them means the host is already under adversary control, making it one of the highest-priority alerts
2. **Tolerance bucketization is the fingerprint** -- periodic communication that varies within a tolerance window is a strong indicator of automated C2
3. **Source port exclusion catches stealthier C2** -- many C2 frameworks use different ephemeral source ports per connection; excluding it from the grouping key prevents the pattern from being diluted
4. **High severity reflects urgency** -- unlike Beaconing (Medium), C2 channel findings start at High because the tolerance-based approach targets a more specific pattern
5. **Complementary to Beaconing** -- bucketization and std dev are different statistical lenses; together they provide broader C2 coverage
