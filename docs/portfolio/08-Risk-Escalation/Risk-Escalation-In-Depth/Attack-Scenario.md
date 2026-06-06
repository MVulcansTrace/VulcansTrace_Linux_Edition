# Risk Escalation — Attack Scenario

A worked example showing how the risk escalation subsystem processes a realistic multi-stage attack from raw logs through escalated findings.

---

## Scenario Overview

An attacker compromises a Linux web server (10.0.0.5) and establishes a C2 channel while simultaneously performing internal reconnaissance. The logs are collected from the host's iptables firewall.

---

## Stage 1: Raw Log Input

The following synthetic iptables log represents the attack:

```
kernel: Jan 19 02:15:01 webserver IN=eth0 SRC=10.0.0.5 DST=8.8.8.8 PROTO=TCP SPT=45123 DPT=443 LEN=64
kernel: Jan 19 02:15:31 webserver IN=eth0 SRC=10.0.0.5 DST=8.8.8.8 PROTO=TCP SPT=45123 DPT=443 LEN=64
kernel: Jan 19 02:16:01 webserver IN=eth0 SRC=10.0.0.5 DST=8.8.8.8 PROTO=TCP SPT=45123 DPT=443 LEN=64
kernel: Jan 19 02:16:31 webserver IN=eth0 SRC=10.0.0.5 DST=8.8.8.8 PROTO=TCP SPT=45123 DPT=443 LEN=64
kernel: Jan 19 02:17:01 webserver IN=eth0 SRC=10.0.0.5 DST=8.8.8.8 PROTO=TCP SPT=45123 DPT=443 LEN=64
kernel: Jan 19 02:17:31 webserver IN=eth0 SRC=10.0.0.5 DST=8.8.8.8 PROTO=TCP SPT=45123 DPT=443 LEN=64
kernel: Jan 19 02:18:01 webserver IN=eth0 SRC=10.0.0.5 DST=8.8.8.8 PROTO=TCP SPT=45123 DPT=443 LEN=64
kernel: Jan 19 02:18:31 webserver IN=eth0 SRC=10.0.0.5 DST=8.8.8.8 PROTO=TCP SPT=45123 DPT=443 LEN=64
kernel: Jan 19 02:30:00 webserver IN=eth0 SRC=10.0.0.5 DST=10.0.0.10 PROTO=TCP SPT=54321 DPT=22 LEN=60
kernel: Jan 19 02:30:05 webserver IN=eth0 SRC=10.0.0.5 DST=10.0.0.11 PROTO=TCP SPT=54321 DPT=22 LEN=60
kernel: Jan 19 02:30:10 webserver IN=eth0 SRC=10.0.0.5 DST=10.0.0.12 PROTO=TCP SPT=54321 DPT=22 LEN=60
kernel: Jan 19 02:30:15 webserver IN=eth0 SRC=10.0.0.5 DST=10.0.0.13 PROTO=TCP SPT=54321 DPT=22 LEN=60
kernel: Jan 19 02:30:20 webserver IN=eth0 SRC=10.0.0.5 DST=10.0.0.14 PROTO=TCP SPT=54321 DPT=22 LEN=60
kernel: Jan 19 02:30:25 webserver IN=eth0 SRC=10.0.0.5 DST=10.0.0.15 PROTO=TCP SPT=54321 DPT=445 LEN=60
kernel: Jan 19 02:30:30 webserver IN=eth0 SRC=10.0.0.5 DST=10.0.0.16 PROTO=TCP SPT=54321 DPT=139 LEN=60
kernel: Jan 19 02:30:35 webserver IN=eth0 SRC=10.0.0.5 DST=10.0.0.17 PROTO=TCP SPT=54321 DPT=3389 LEN=60
```

---

## Stage 2: Normalization

`LogNormalizer.Normalize` parses all 16 lines into `UnifiedEvent` records:

| # | Timestamp | SourceIP | DestIP | DPT | Protocol |
|---|-----------|----------|--------|-----|----------|
| 1-8 | 02:15 - 02:18 (30s intervals) | 10.0.0.5 | 8.8.8.8 | 443 | TCP |
| 9-16 | 02:30 - 02:30 | 10.0.0.5 | 10.0.0.10-17 | 22/445/139/3389 | TCP |

Total lines: 16 | Parsed: 16 | Parse errors: 0

---

## Stage 3: Detector Output

### Layer 1 — Baseline Detectors

**BeaconingDetector**: Finds 8 events from 10.0.0.5 to 8.8.8.8:443 at ~30-second intervals.

```
Finding { Category = "Beaconing", Severity = Medium, SourceHost = "10.0.0.5",
          Target = "8.8.8.8:443", ShortDescription = "Regular beaconing from 10.0.0.5" }
```

**LateralMovementDetector**: Finds connections from 10.0.0.5 to 8 distinct internal hosts (10.0.0.10 through 10.0.0.17) on admin ports within a 35-second window.

```
Finding { Category = "LateralMovement", Severity = High, SourceHost = "10.0.0.5",
          Target = "10.0.0.10-17", ShortDescription = "Lateral movement across internal hosts" }
```

### Layer 2 — Linux Deep Inspection Detectors

No Linux-specific anomalies detected in this scenario (no flag anomalies, MAC spoofing, or interface hopping).

### Layer 3 — Advanced Detectors

No advanced detector fires in this scenario. The 30-second beacon interval is below the Medium profile's `C2MinIntervalSeconds` threshold of 60 seconds.

---

## Stage 4: Pre-Escalation Finding Summary

| # | Category | Severity | SourceHost |
|---|----------|----------|------------|
| 1 | Beaconing | Medium | 10.0.0.5 |
| 2 | LateralMovement | High | 10.0.0.5 |

Both findings share `SourceHost = "10.0.0.5"`.

---

## Stage 5: Risk Escalation

`RiskEscalator.Escalate` processes the findings:

1. **Group by host**: Both findings are in the `10.0.0.5` group
2. **Build category set**: `{ "Beaconing", "LateralMovement" }`
3. **Evaluate rules**:
   - Beaconing + LateralMovement: `"Beaconing"` exists AND `"LateralMovement"` exists -> **TRUE**
   - FlagAnomaly + PortScan: `"FlagAnomaly"` not in set -> FALSE
   - MacSpoofing + InterfaceHopping: `"MacSpoofing"` not in set -> FALSE
4. **shouldEscalate = TRUE**
5. **Escalate the participating findings**:

```csharp
var correlationSignal = new EvidenceSignal
{
    Name = "Cross-detector correlation",
    Source = EvidenceSignal.BehaviorSource,
    Explanation = $"Correlated {f.Category} with complementary threat pattern on same host within 24h"
};
var escalatedSignals = f.EvidenceSignals.Concat(new[] { correlationSignal }).ToList();
result.Add(f with
{
    Severity = Severity.Critical,
    Confidence = FindingConfidenceCalculator.Calculate(escalatedSignals),
    EvidenceSignals = escalatedSignals
});
```

---

## Stage 6: Post-Escalation Finding Summary

| # | Category | Severity | Confidence | SourceHost | Escalated |
|---|----------|----------|------------|------------|-----------|
| 1 | Beaconing | Critical | High | 10.0.0.5 | Yes (was Medium) |
| 2 | LateralMovement | Critical | High | 10.0.0.5 | Yes (was High) |

---

## Stage 7: Severity Filter

At Medium intensity, `MinSeverityToShow = Severity.Medium`. Both Critical findings pass the filter.

At Low intensity, `MinSeverityToShow = Severity.High`. Both Critical findings still pass the filter.

**Result**: Regardless of intensity level, the analyst always sees the escalated Critical findings for this host.

---

## What Changed

Without escalation, the analyst would see separate Beaconing and LateralMovement findings on the same host and would need to manually correlate them. With escalation, the analyst sees Critical findings for the correlated behaviors, clearly indicating a compromised machine that is both calling home and spreading internally.

The escalation reflects the actual threat: a host exhibiting both C2 communication and lateral movement is actively controlled by an attacker and must be investigated immediately.

---

## Security Takeaways

- The Beaconing + LateralMovement correlation rule directly models the attacker behavior of establishing C2 while pivoting internally — one of the most common post-compromise patterns
- Escalation promotes only the categories that participate in the matched rule, preserving precise severity semantics for unrelated findings on the same host
- Post-escalation severity filtering means the Critical findings survive even the most restrictive intensity profile
- The synthetic scenario maps directly to the real-world test patterns in [RealWorldAttackScenarioTests.cs](../../../../VulcansTrace.Linux.Tests/Integration/RealWorldAttackScenarioTests.cs) and the escalation integration test in [SentryAnalyzerTests.cs](../../../../VulcansTrace.Linux.Tests/Integration/SentryAnalyzerTests.cs)
