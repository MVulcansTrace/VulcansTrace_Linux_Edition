# Flood Detection — Why This Matters

## Security Problem

Denial-of-service attacks are among the most frequently executed network attacks. Whether launched by external adversaries, compromised internal hosts participating in a botnet, or misconfigured applications, a flood of connection attempts can degrade or completely disable critical services. The challenge is distinguishing a genuine DoS attack from a sudden but legitimate traffic spike — such as a batch job starting, a CDN flush, or a software update rollout.

Firewall logs capture every connection attempt, but the volume of data makes manual review impossible. Without automated flood detection, operators learn about attacks only when services actually fail — by which point the damage to availability and user trust has already occurred.

The flood detector solves this by monitoring per-source connection volume within a sliding time window, automatically identifying IPs that exceed operational thresholds.

---

## Implementation Overview

The detector operates on pre-normalized `UnifiedEvent` records through a three-stage pipeline:

1. **Group by source** — partition events by originating IP to evaluate each source independently
2. **Temporal analysis** — sort events by timestamp and apply a two-pointer sliding window
3. **Threshold detection** — count events within the window and emit a finding when volume exceeds the configured minimum

The implementation is compact production C#.

---

## Operational Benefits

| Benefit | Description |
|---|---|
| Proactive availability protection | Detects high-volume sources to enable response before services degrade |
| Rapid source identification | Finding includes the exact source IP and event count (in the Details string) for immediate blocking |
| Profile-tunable sensitivity | Three threshold levels match different operational risk tolerances |
| Minimal computational footprint | Two-pointer window keeps analysis fast even on million-event log files |
| Burst-aware output | One finding per contiguous burst limits duplicate alerts while capturing repeated episodes |

---

## Security Principles Applied

| Principle | Application |
|---|---|
| Defense in depth | Operates as a separate detection layer independent of upstream firewalls and IDS |
| Least privilege | No network access, no state mutation — purely analytical |
| Fail-safe defaults | Guard clause returns empty results if the detector is disabled or input is empty |
| Observability | Findings include exact event count and time window for forensic analysis; RiskEscalator does not currently escalate Flood findings (no correlation pair includes Flood) |
| Separation of concerns | Detector is decoupled from normalization, escalation, and evidence packaging |

---

## Implementation Evidence

- [FloodDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/FloodDetector.cs) — core detection with two-pointer window
- [AnalysisProfile.cs](../../../../VulcansTrace.Linux.Engine/AnalysisProfile.cs) — configurable thresholds
- [FloodDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/Baseline/FloodDetectorTests.cs) — test suite

---

> **Elevator Pitch:** This detector is the network's pulse monitor — watching for any single IP that starts hammering connections faster than the network can handle, and flagging it before services go down. In clean C#, it transforms millions of firewall log entries into actionable alerts.

---

## Security Takeaways

- Flood detection protects service availability — the most fundamental security property
- The two-pointer sliding window provides accurate temporal detection without boundary artifacts
- Profile-driven thresholds allow operations teams to calibrate to their specific traffic patterns
- Focused tests validate threshold behavior across edge cases and multi-source scenarios
- Burst-aware design limits duplicate findings while capturing repeated attack episodes
