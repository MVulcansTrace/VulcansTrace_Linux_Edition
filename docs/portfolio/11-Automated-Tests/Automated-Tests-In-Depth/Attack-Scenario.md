# Attack Scenario: Automated Tests

## The Security Problem

An attacker performs a TCP SYN port scan against a Linux server, generating 50 iptables log entries across 20 common service ports over 10 minutes. The port scan detector must correctly identify this as reconnaissance activity. The test suite must prove that the detector fires at the right threshold, rejects benign traffic below the threshold, and produces findings with enough context for analyst triage.

---

## Worked Example

Consider the `Detect_PortScanAboveMediumThreshold_ReturnsFinding` test in `PortScanDetectorTests.cs`:

```csharp
[Fact]
public void Detect_PortScanAboveMediumThreshold_ReturnsFinding()
{
    // Arrange
    var builder = new LogScenarioBuilder();
    var log = builder
        .BuildPortScan(targetCount: 20, duration: TimeSpan.FromMinutes(3))
        .Generate();
    var events = _normalizer.Normalize(log).Events;
    var profile = new AnalysisProfile
    {
        EnablePortScan = true,
        PortScanMinPorts = 15,
        PortScanWindowMinutes = 5
    };

    // Act
    var findings = _detector.Detect(events, profile, CancellationToken.None).ToList();

    // Assert
    Assert.Single(findings);
    Assert.Equal("PortScan", findings[0].Category);
}
```

---

## Detection Walkthrough

| Step | Operation | Result |
|---|---|---|
| 1. Generate synthetic log | `LogScenarioBuilder.BuildPortScan(targetCount: 20, duration: 3 min)` | 20 iptables lines targeting common service ports |
| 2. Normalize to events | `_normalizer.Normalize(log).Events` | 20 `UnifiedEvent` objects with parsed IPs, ports, timestamps |
| 3. Configure profile | `PortScanMinPorts = 15`, `PortScanWindowMinutes = 5` | Medium intensity thresholds |
| 4. Run detector | `_detector.Detect(events, profile, CancellationToken.None)` | Detector groups by source, windows by time, counts distinct destination ports |
| 5. Assert finding count | `Assert.Single(findings)` | Exactly 1 finding emitted |
| 6. Assert finding category | `Assert.Equal("PortScan", findings[0].Category)` | Finding correctly categorized |

---

## Boundary Validation

The test suite validates the threshold edge with three complementary tests:

```
    Finding Emitted?
         │
    ┌────┼────────────────────────────────────────────┐
    │    │                                            │
    ▼    ▼                                            ▼
  targetCount=14     targetCount=15     targetCount=20,100
  ┌──────────┐       ┌──────────┐       ┌──────────┐
  │  BELOW   │       │  AT      │       │  ABOVE   │
  │  Empty   │       │  Single  │       │  Single  │
  │  finding │       │  finding │       │  finding │
  └──────────┘       └──────────┘       └──────────┘
   Correct: ✗         Correct: ✓         Correct: ✓
   (no false pos)     (boundary incl)    (scalability)
```

- `targetCount: 14` — Asserts `Empty(findings)`. Proves 14 distinct destinations do not trigger a threshold of 15. Prevents false positives.
- `targetCount: 15` — Asserts `Single(findings)`. Proves the `>=` comparison includes the boundary value. The exact edge is correct.
- `targetCount: 20` and `targetCount: 100` — Asserts `Single(findings)`. Proves detection scales to larger scans without producing duplicate findings.

---

## Full-Pipeline Validation

The same attack pattern is validated end-to-end in `SentryAnalyzerTests`:

```csharp
[Fact]
public void Analyze_PortScanDetectsCorrectly()
{
    var builder = new LogScenarioBuilder();
    var log = builder
        .BuildPortScan(targetCount: 20, duration: TimeSpan.FromMinutes(5))
        .Generate();

    var result = _analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None);

    Assert.True(result.ParsedLines > 0);
    Assert.Contains(result.Findings, f => f.Category == "PortScan");
}
```

This test feeds raw log text to the full `SentryAnalyzer` — which runs through normalization, all 14 detectors, and risk escalation — and verifies the finding survives the entire pipeline. This catches bugs that unit tests cannot: findings lost during aggregation, risk escalation errors, or profile misapplication.

---

## Real-World Attack Scenario Test

The `RealWorldAttackScenarioTests` class exercises multi-attack scenarios:

```csharp
[Fact]
public void Analyze_RealWorld_Mixed_Attack_Scenario_DetectsMultiple()
{
    var ddosLog = GenerateFloodAttackLog(TimeSpan.FromMinutes(2), 500);
    var portScanLog = GeneratePortScanAttackLog(30, TimeSpan.FromMinutes(5));
    var c2Log = GenerateC2ChannelLog(TimeSpan.FromMinutes(10), TimeSpan.FromHours(1));

    var mixedLog = ddosLog + Environment.NewLine + portScanLog + Environment.NewLine + c2Log;

    var result = _analyzer.Analyze(mixedLog, IntensityLevel.Medium, CancellationToken.None);

    Assert.Contains(result.Findings, f => f.Category == "PortScan" || f.Category == "Flood");
    Assert.Contains(result.Findings, f => f.Category == "C2Channel");
    Assert.True(result.Findings.Count > 2);
}
```

This test combines three attack patterns — DDoS flood, port scan, and C2 channel — into a single log and verifies that the analyzer correctly detects multiple attack types simultaneously.

---

## Security Value

| Aspect | Value |
|---|---|
| Threshold edge validation | Proves the detection boundary is exactly where configuration says it is |
| False-positive prevention | Below-threshold tests prove benign traffic is not flagged |
| Pipeline integrity | Integration tests prove findings survive normalization, detection, and escalation |
| Multi-attack detection | Scenario tests prove the analyzer handles concurrent attack patterns |
| Property verification | Tests assert on finding category, severity, and details — not just existence |

---

## Security Takeaways

1. Boundary-value tests at threshold 15 with inputs 14, 15, and 20 prove the detection edge is exact in both directions
2. The unit-to-integration progression validates detection logic in isolation and then proves it works in the full pipeline
3. Multi-attack scenario tests verify that concurrent attack patterns do not interfere with each other's detection
4. The `LogScenarioBuilder` generates realistic port sequences from common service ports, making synthetic tests representative of real scan patterns
5. Finding property assertions ensure that detected attacks carry enough context (category, host, description) for analyst triage
