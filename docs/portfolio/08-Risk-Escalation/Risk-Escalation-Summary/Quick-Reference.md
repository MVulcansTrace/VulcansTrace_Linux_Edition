# Risk Escalation — Quick Reference

A single-page reference for the detection pipeline, correlation rules, severity levels, and key types.

---

## Pipeline Overview

```
  Raw Log
    |
    v
+-------------------+
|  LogNormalizer    |   Format auto-detect, regex parse,
|                   |   validate, produce UnifiedEvent[]
+-------------------+
    |
    v
+-------------------+
|  Parse Error Cap  |   Keep first 500 errors only
|  (Max 500)        |
+-------------------+
    |
    v
+---------------------------+
|  Layer 1: Baseline        |   PortScan, Flood, LateralMovement,
|  Detectors                |   Beaconing, PolicyViolation, Novelty
+---------------------------+
    |  try/catch per detector
    v
+---------------------------+
|  Layer 2: Linux Deep      |   FlagAnomaly, MacSpoofing,
|  Inspection Detectors     |   KernelModule, InterfaceHopping,
|                           |   UnusualPacketSize
+---------------------------+
    |  try/catch per detector
    v
+---------------------------+
|  Layer 3: Advanced        |   C2Channel,
|  Detectors                |   PrivilegeEscalation
+---------------------------+
    |  try/catch per detector
    v
+---------------------------+
|  RiskEscalator            |   Group by SourceHost,
|                           |   evaluate 3 correlation rules,
|                           |   escalate participating findings
+---------------------------+
    |
    v
+---------------------------+
|  Beaconing/C2 Dedupe      |   Keep the stronger C2 finding
|                           |   for overlapping tuples
+---------------------------+
    |
    v
+---------------------------+
|  Severity Filter          |   Remove findings below
|  (MinSeverityToShow)      |   profile threshold
+---------------------------+
    |
    v
+---------------------------+
|  Finding Cap              |   Apply MaxFindingsPerDetector
|                           |   after severity filtering
+---------------------------+
    |
    v
  AnalysisResult
  (Entries, Findings, Warnings, ParseErrors, Stats)
```

---

## Correlation Rules

| # | Category A | Category B | Escalated Severity | Threat Interpretation |
|---|-----------|-----------|--------------------|-----------------------|
| 1 | Beaconing | LateralMovement | Critical | C2 communication with internal pivoting |
| 2 | FlagAnomaly | PortScan | Critical | Evasion combined with reconnaissance |
| 3 | MacSpoofing | InterfaceHopping | Critical | Network-control bypass |

All rules are evaluated per host. If any rule fires, only findings whose categories participate in the matched rule are escalated to Critical; other findings on the same host are preserved at their original severity.

---

## Severity Levels

| Level | Value | Meaning |
|-------|-------|---------|
| Info | 0 | Informational, no immediate action |
| Low | 1 | Monitor for patterns |
| Medium | 2 | Investigate when resources permit |
| High | 3 | Investigate promptly |
| Critical | 4 | Immediate investigation required |

`MinSeverityToShow` in the `AnalysisProfile` filters output by severity:
- Low intensity: High+ only
- Medium intensity: Medium+ only
- High intensity: Info and above (all findings)

---

## Key Types

| Type | File | Role |
|------|------|------|
| `RiskEscalator` | RiskEscalator.cs | Host-scoped correlation and escalation |
| `SentryAnalyzer` | SentryAnalyzer.cs | Full pipeline orchestrator |
| `AnalysisProfile` | AnalysisProfile.cs | Detector thresholds and severity filter |
| `Finding` (record) | Finding.cs | Immutable finding with `with` support |
| `Severity` (enum) | Severity.cs | Five-level severity scale |
| `IDetector` | IDetector.cs | Detector contract |
| `AnalysisResult` | — | Final output with entries, findings, warnings |

---

## Intensity Profile Thresholds

| Setting | Low | Medium | High |
|---------|-----|--------|------|
| PortScanMinPorts | 30 | 15 | 8 |
| FloodMinEvents | 400 | 200 | 100 |
| LateralMinHosts | 6 | 4 | 3 |
| BeaconMinEvents | 8 | 6 | 4 |
| MinSeverityToShow | High | Medium | Info |
| Novelty enabled | No | Yes | Yes |
| C2 detection enabled | No | Yes | Yes |

---

## Security Takeaways

- The pipeline runs three independent detection layers with fault isolation, meaning no single detector failure can suppress escalation
- Correlation rules operate on the host scope because multi-category findings from the same source IP represent a higher-confidence threat than isolated indicators
- The severity filter is applied after escalation so that escalated Critical findings are always surfaced regardless of the intensity profile
