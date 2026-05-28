# Lateral Movement Detection — Why This Matters

## Security Problem

After gaining initial access to a single host, attackers rarely stay put. They move laterally through the internal network — compromising additional servers, escalating privileges, and positioning themselves near high-value assets like domain controllers, databases, and file servers. This lateral movement phase is where attackers transform a single-machine compromise into a full-scale breach.

Traditional perimeter defenses miss lateral movement because the traffic never crosses the network boundary. Firewalls logging internal-to-internal connections generate enormous volume, making manual review impossible. Without automated detection, attackers can operate for days or weeks inside a network before reaching their objective.

The lateral movement detector solves this by automatically identifying the specific pattern that distinguishes malicious pivoting from normal internal communication: a single internal host connecting to many other internal hosts on administrative ports within a short time window.

---

## Implementation Overview

The detector operates on pre-normalized `UnifiedEvent` records and applies a three-stage pipeline:

1. **Scope reduction** — filter to internal-to-internal events on configurable admin ports (profile default: 445, 3389, 22)
2. **Temporal analysis** — group by source IP and apply a two-pointer sliding window over sorted events
3. **Threshold detection** — count distinct destination IPs in the window and emit a finding when the count exceeds the configured minimum

The implementation is compact production C#, making it auditable, testable, and maintainable.

---

## Operational Benefits

| Benefit | Description |
|---|---|
| Kill chain interruption | Detects attackers during the lateral movement phase, before they reach crown jewels |
| Low false-positive design | Admin-port and distinct-host filters significantly reduce benign broadcast and service discovery traffic |
| Configurable sensitivity | Three profile levels let operators tune detection to their network's risk tolerance |
| Efficient windowed scan | Two-pointer window minimizes pointer recomputation, keeping overhead bounded on large log sets |
| Immediate triage context | Finding includes source IP, host count, and time window — key context for initial response |

---

## Security Principles Applied

| Principle | Application |
|---|---|
| Defense in depth | Operates behind the perimeter on internal traffic that external defenses cannot see |
| Least privilege | Focuses on admin ports where unauthorized access has highest impact |
| Separation of concerns | Detector is decoupled from normalization and evidence packaging |
| Fail-safe defaults | Disabled by default if profile flags are not explicitly set |
| Observability | Every finding includes source IP, host count, time window, and severity for human triage |

---

## Implementation Evidence

- [LateralMovementDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/LateralMovementDetector.cs) — core detection with two-pointer window
- [IpClassification.cs](../../../../VulcansTrace.Linux.Engine/Net/IpClassification.cs) — RFC 1918 / IPv6 ULA classification
- [AnalysisProfile.cs](../../../../VulcansTrace.Linux.Engine/AnalysisProfile.cs) — configurable thresholds
- [LateralMovementDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/Baseline/LateralMovementDetectorTests.cs) — test suite

---

> **Elevator Pitch:** This detector catches the moment an attacker starts pivoting through your internal network — flagging when a single internal host touches multiple internal machines on SMB, RDP, or SSH within minutes. It's the tripwire that turns an unnoticed breach into an alerted incident.

---

## Security Takeaways

- Lateral movement detection operates on internal traffic that perimeter defenses fundamentally cannot see
- The two-pointer sliding window provides accurate temporal detection with bounded per-window cost
- Admin-port filtering maximizes signal quality by focusing on the protocols attackers actually use for pivoting
- Profile-driven thresholds allow operations teams to adjust sensitivity without code changes
- The 5.7:1 test-to-code ratio ensures the detection logic is thoroughly validated across edge cases

---

## Design Notes

- **Multiple findings per source possible:** The detector emits one finding per contiguous above-threshold burst. If the same host exhibits lateral movement in multiple separate time windows, each burst produces its own finding.
- **Severity escalation:** When the `RiskEscalator` detects that the same source host also triggered a Beaconing finding, the severity is escalated from High to Critical — reflecting the higher confidence that the host is compromised and under command-and-control.
