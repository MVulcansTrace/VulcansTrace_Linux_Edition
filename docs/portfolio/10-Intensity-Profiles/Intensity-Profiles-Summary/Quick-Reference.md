# Intensity Profiles — Quick Reference

## Profile Resolution Pipeline

1. **Select intensity** — user or caller chooses Low, Medium, or High
2. **Resolve profile** — `AnalysisProfileProvider.GetProfile(level)` maps enum to sealed record
3. **Override check** — SentryAnalyzer applies optional `overrideProfile` if provided (line 114)
4. **Distribute** — resolved profile passed to every detector and later used for severity filtering and finding caps
5. **Execute** — all detectors read enable flags and thresholds from the shared profile object

---

## Detector Enable Flags by Profile

| Detector | Enable Property | Low | Medium | High |
|---|---|---|---|---|
| Port Scan | `EnablePortScan` | true | true | true |
| Flood | `EnableFlood` | true | true | true |
| Lateral Movement | `EnableLateralMovement` | true | true | true |
| Beaconing | `EnableBeaconing` | true | true | true |
| Policy Violation | `EnablePolicy` | true | true | true |
| Novelty | `EnableNovelty` | false | true | true |
| TCP Flag Anomaly | `EnableFlagAnomaly` | true | true | true |
| MAC Spoofing | `EnableMacSpoofing` | true | true | true |
| Kernel Module | `EnableKernelModule` | false | true | true |
| Interface Hopping | `EnableInterfaceHopping` | false | true | true |
| Unusual Packet Size | `EnableUnusualPacketSize` | false | true | true |
| C2 Channel | `EnableC2Detection` | false | true | true |
| Privilege Escalation | `EnablePrivilegeEscalationDetection` | false | true | true |

---

## Threshold Comparison

| Parameter | Low | Medium | High |
|---|---|---|---|
| **Port Scan** | | | |
| PortScanMinPorts | 30 | 15 | 8 |
| PortScanWindowMinutes | 5 | 5 | 5 |
| **Flood** | | | |
| FloodMinEvents | 400 | 200 | 100 |
| FloodWindowSeconds | 60 | 60 | 60 |
| **Lateral Movement** | | | |
| LateralMinHosts | 6 | 4 | 3 |
| LateralWindowMinutes | 10 | 10 | 10 |
| **Beaconing** | | | |
| BeaconMinEvents | 8 | 6 | 4 |
| BeaconStdDevThreshold | 3.0 | 5.0 | 8.0 |
| BeaconMinIntervalSeconds | 60 | 30 | 10 |
| BeaconMaxIntervalSeconds | 900 | 900 | 900 |
| **C2 Channel** | | | |
| C2ToleranceSeconds | 10.0 | 5.0 | 8.0 |
| C2MinIntervalSeconds | 120 | 60 | 30 |
| C2MaxIntervalSeconds | 3600 | 1800 | 1800 |
| C2MinOccurrences | 5 | 3 | 2 |
| C2MinPatternEvents | 10 | 6 | 4 |
| C2MinGroupSize | 4 | 3 | 3 |
| **Privilege Escalation** | | | |
| PrivilegeSpikeWindowMinutes | 10 | 5 | 10 |
| **Output Filter** | | | |
| MinSeverityToShow | High | Medium | Info |

---

## Shared Settings (All Profiles)

| Setting | Value |
|---|---|
| AdminPorts | [445, 3389, 22] |
| DisallowedOutboundPorts | [21, 23, 445] |
| PortScanMaxEntriesPerSource | null (unlimited) |
| BeaconMaxSamplesPerTuple | 200 |
| BeaconMinDurationSeconds | 120 |
| BeaconTrimPercent | 0.1 |
| MaxFindingsPerDetector | 100 |

---

## Downstream Pipeline

```
  IntensityLevel (Low / Medium / High)
        |
        v
  AnalysisProfileProvider.GetProfile()
        |
        v
  AnalysisProfile (sealed record, immutable)
        |
        v
  SentryAnalyzer.Analyze()
   ├─ Layer 1: Baseline detectors (6)
   ├─ Layer 2: Linux Deep Inspection (5)
   ├─ Layer 3: Advanced detectors (2)
   ├─ Risk Escalation
   ├─ Beaconing/C2 dedupe
   ├─ MinSeverity filter
   └─ MaxFindingsPerDetector cap
        |
        v
  AnalysisResult (filtered Findings)
```

---

## File References

| File | Path | Lines |
|---|---|---|
| AnalysisProfile.cs | `VulcansTrace.Linux.Engine/` | 195 |
| AnalysisProfileProvider.cs | `VulcansTrace.Linux.Engine/Configuration/` | 239 |
| IntensityLevel.cs | `VulcansTrace.Linux.Engine/` | 18 |
| SentryAnalyzer.cs | `VulcansTrace.Linux.Engine/` | 303 |
| ProfileComparisonTests.cs | `VulcansTrace.Linux.Tests/Integration/` | 123 |

---

## Security Takeaways

- 7 of 13 detectors are enabled in all profiles; 6 advanced detectors activate only at Medium and above
- Thresholds decrease roughly 2x from Low to Medium and 2x again from Medium to High
- MinSeverityToShow is the visibility gate before the per-category finding cap — Low profile may detect Medium-severity findings but filters them before output
- Shared policy lists (AdminPorts, DisallowedOutboundPorts) ensure consistent policy enforcement regardless of intensity
