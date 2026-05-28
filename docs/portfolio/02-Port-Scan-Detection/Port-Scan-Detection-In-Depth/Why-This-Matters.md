# Why This Matters: Port Scan Detection

## The Security Problem

Port scanning is the first active step in nearly every network-based attack. Before an attacker can exploit a vulnerability, they must discover which services are running and which ports are open. Tools like Nmap, Masscan, and ZMap can sweep thousands of ports per second, and the resulting firewall log entries are often buried among legitimate traffic.

Without automated detection, port scans go unnoticed. Network administrators rarely inspect raw iptables logs line by line, and the volume of normal connection events dwarfs reconnaissance traffic. A single scan of 1,024 ports from one attacker IP produces the same number of log entries as a busy web server handles in seconds — making manual identification impractical.

The port scan detector solves this by automatically identifying source IPs that contact an unusually large number of distinct destination ports within a time window, separating aggressive reconnaissance from background noise.

---

## Implementation Overview

The detector operates on the normalized event stream. It groups events by source IP, orders them chronologically, optionally truncates high-volume sources to the latest events with a warning (when `PortScanMaxEntriesPerSource` is configured; no default profile sets a cap), scans a sliding time window, and emits a Medium-severity finding when the count of distinct destination ports in any window exceeds a configurable threshold.

---

## Operational Benefits

| Benefit | How It Helps |
|---|---|
| Early warning | Detects reconnaissance before exploitation begins |
| Prioritized alerts | Medium severity by default; participating PortScan and FlagAnomaly findings are escalated to Critical when correlated (note: Low profile's severity filter suppresses Medium findings, including uncorrelated port scans — use Medium or High profiles to ensure visibility) |
| Tunable sensitivity | Three intensity profiles (Low/Medium/High) adapt thresholds to the network environment |
| Transparent truncation | Warnings are emitted when high-volume sources are capped, preserving analyst trust (opt-in via `PortScanMaxEntriesPerSource`; no default profile enables truncation) |
| Low false-positive design | Distinct-port counting in time windows avoids triggering on repeated connections to the same service |

---

## Security Principles Applied

| Principle | Application |
|---|---|
| Defense in depth | Port scan findings feed the `RiskEscalator`, which correlates them with other detector outputs |
| Least surprise | Findings include the source IP, target count, time range, and window size so analysts can verify quickly |
| Fail safe | If cancellation is requested mid-scan, partial results are not emitted — findings are only added when fully formed |
| Transparency | Detector warnings surface truncation events to the analyst rather than silently dropping data (truncation is opt-in via `PortScanMaxEntriesPerSource`; no default profile sets a cap) |
| Configurable response | Threshold parameters live in `AnalysisProfile`, not in detector code, allowing per-deployment tuning |

---

## Implementation Evidence

- [PortScanDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/PortScanDetector.cs) — detector implementation
- [AnalysisProfile.cs](../../../../VulcansTrace.Linux.Engine/AnalysisProfile.cs) — threshold configuration record
- [AnalysisProfileProvider.cs](../../../../VulcansTrace.Linux.Engine/Configuration/AnalysisProfileProvider.cs) — intensity presets
- [PortScanDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/Baseline/PortScanDetectorTests.cs) — test suite
- [RiskEscalator.cs](../../../../VulcansTrace.Linux.Engine/RiskEscalator.cs) — correlation escalation

---

## Elevator Pitch

> The port scan detector takes a stream of normalized firewall events and identifies hosts conducting network reconnaissance by counting distinct destination ports within sliding time windows. It is cancellation-safe, emits warnings when high-volume sources are truncated (opt-in via `PortScanMaxEntriesPerSource`), and feeds a downstream risk escalator that correlates its findings with other detectors for higher-confidence alerts when correlated patterns exist.

---

## Security Takeaways

1. Port scanning is a prerequisite step in most attacks — detecting it provides an early warning window
2. Time-windowed distinct-port counting separates aggressive sweeps from benign repeated traffic patterns
3. The pre-window gate skips low-activity sources entirely, reducing both compute cost and false positives
4. Truncation warnings ensure analysts know when data was dropped, maintaining trust in the results (available when `PortScanMaxEntriesPerSource` is manually configured; no default profile enables it)
5. Downstream correlation by `RiskEscalator` evaluates port scans alongside other detector findings for the same host, escalating the participating categories to Critical when correlated patterns (such as Flag Anomaly) are present — combined signals produce stronger alerts when they exist
6. Profile-based thresholds allow defenders to adapt detection sensitivity to their specific network baseline
