# Policy Violation Detection — Quick Reference

## Algorithm Steps

1. **Guard** — return empty if `EnablePolicy` is false or events list is empty
2. **Build disallowed set** — `HashSet<int>` from `profile.DisallowedOutboundPorts` (default [21, 23, 445])
3. **Iterate events** — single pass over all events
4. **Filter per event** — skip if source is not internal, destination is not external, or port is not disallowed
5. **Group** — collect matching events by `(SourceIP, DstPort)` into a dictionary
6. **Emit finding** — one finding per group with aggregated counts and time range

---

## Configuration Parameters

| Parameter | Type | Low Profile | Medium Profile | High Profile |
|---|---|---|---|---|
| `EnablePolicy` | bool | true | true | true |
| `DisallowedOutboundPorts` | int[] | [21, 23, 445] | [21, 23, 445] | [21, 23, 445] |

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
  PolicyViolationDetector.Detect()
      |
      v
  Finding[] { Category="PolicyViolation", Severity=High }
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
| `Category` | `FindingCategories.PolicyViolation` |
| `Severity` | `High` |
| `SourceHost` | Grouped source IP |
| `Target` | `"{DestIP}:{DstPort}"` if one destination, `"multiple hosts:{DstPort}"` if multiple |
| `TimeRangeStart` | `minTime` across group |
| `TimeRangeEnd` | `maxTime` across group |
| `ShortDescription` | `"Disallowed outbound port {Port} from {SourceIP}"` |
| `Details` | `"{Count} outbound connection(s) to {DistinctTargets} destination(s) on disallowed port {Port} from {SourceIP}."` |

---

## Complexity

| Dimension | Value |
|---|---|
| Time | O(n) — single pass, O(1) checks per event |
| Space | O(k) — k groups in dictionary |
| State | Dictionary grouping by (SourceIP, DstPort) |

---

## MITRE ATT&CK Mapping

| Technique | ID | Tactic | Detection |
|---|---|---|---|
| Application Layer Protocol | T1071 | Command and Control (TA0011) | Primary — unusual protocol usage |
| Exfiltration Over Alternative Protocol | T1048 | Exfiltration (TA0010) | Primary — FTP/Telnet exfiltration |
| Exfiltration (Parent Tactic) | TA0010 | — | Outbound policy violations often indicate data theft |

---

## Evasion Summary

| Evasion Technique | Effectiveness | Mitigation |
|---|---|---|
| Port forwarding / tunneling | Full | Detect tunnel endpoints or use DPI |
| Protocol encapsulation | High | Application-layer analysis required |
| Allowed-port abuse | Full | Add more ports to disallowed list |
| Encrypted traffic on disallowed ports | Low | Connection is still detected |

---

## File References

| File | Path | Role |
|---|---|---|
| PolicyViolationDetector.cs | `VulcansTrace.Linux.Engine/Detectors/` | Detection logic |
| IpClassification.cs | `VulcansTrace.Linux.Engine/Net/` | Internal/external network classification |
| AnalysisProfile.cs | `VulcansTrace.Linux.Engine/` | Disallowed port configuration |
| PolicyViolationDetectorTests.cs | `VulcansTrace.Linux.Tests/Detectors/Baseline/` | Detector behavior coverage |
