# Why This Matters: Privilege Escalation Detection

## The Security Problem

Privilege escalation is the pivotal moment in an attack where an adversary transitions from limited access to administrative control. Once an attacker gains root or admin privileges on a Linux server, they can install persistent backdoors, exfiltrate sensitive data, disable security controls, and pivot to other systems on the network.

Two network-visible patterns indicate privilege escalation attempts:

1. **Brute-force attacks against admin services** — An attacker sends rapid-fire login attempts against SSH, database, or remote desktop services, hoping to guess credentials or exploit weak passwords. A single source IP hammering SSH port 22 with 50 login attempts in 2 minutes is a strong indicator of a brute-force attack.

2. **Admin port enumeration** — An attacker systematically probes multiple administrative services (SSH, RDP, VNC, database ports) to find the weakest entry point. A single source attempting connections to ports 22, 3389, 5900, and 5432 within a few minutes is not normal user behavior — it is service reconnaissance targeting administrative interfaces.

Without automated detection, both patterns are buried in firewall logs. A busy SSH server may log hundreds of legitimate connections per hour, and database administrators routinely connect to multiple database instances. The detector must distinguish aggressive attack patterns from normal administrative traffic.

---

## Implementation Overview

The detector is a 233-line implementation that operates on the normalized event stream. It filters events targeting a curated set of administrative ports, groups them by source IP, and runs two complementary sub-detectors: `DetectAdminSpikes` flags high-volume bursts using a sliding time window (High severity), and `DetectAdminPortSweeps` flags multi-port service enumeration using a sliding time window with dictionary port tracking (Medium severity). The detector is profile-gated and adapts its time window based on analysis intensity.

---

## Operational Benefits

| Benefit | How It Helps |
|---|---|
| Early warning | Detects brute-force and enumeration attacks before successful compromise |
| Dual signal coverage | Spike detection catches brute force; sweep detection catches service enumeration |
| Prioritized alerts | High severity for spikes (immediate threat), Medium for sweeps (reconnaissance) |
| Tunable sensitivity | Three intensity profiles adapt time windows from 5 to 10 minutes |
| Extensible port coverage | Profile-supplied admin ports merge with the baseline, supporting custom environments |
| Profile-gated activation | Disabled in Low profile to prevent false positives in admin-heavy environments |

---

## Security Principles Applied

| Principle | Application |
|---|---|
| Defense in depth | Privilege escalation findings complement port scan, lateral movement, and beaconing detectors |
| Least surprise | Findings include source IP, port list, time range, and attempt count for rapid analyst verification |
| Fail safe | If cancellation is requested mid-analysis, partial results are discarded — findings are only added when fully formed |
| Configurable response | Time windows and admin port lists live in `AnalysisProfile`, not in detector code |
| Separation of concerns | Two focused sub-detectors each handle one attack pattern, keeping the logic testable and maintainable |

---

## Implementation Evidence

- [PrivilegeEscalationDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/PrivilegeEscalationDetector.cs) — detector implementation (233 lines)
- [AnalysisProfile.cs](../../../../VulcansTrace.Linux.Engine/AnalysisProfile.cs) — threshold configuration record (195 lines)
- [AnalysisProfileProvider.cs](../../../../VulcansTrace.Linux.Engine/Configuration/AnalysisProfileProvider.cs) — intensity presets (239 lines)
- [PrivilegeEscalationDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/PrivilegeEscalationDetectorTests.cs) — test suite (679 lines)

---

## Elevator Pitch

> The privilege escalation detector takes a stream of normalized firewall events and, in 233 lines, identifies two critical attack patterns: brute-force admin-port bursts and multi-port admin service sweeps. It uses dual sub-detectors with sliding time windows, adapts sensitivity through profile-based configuration, and is cancellation-safe for reliable operation on large log datasets.

---

## Security Takeaways

1. Privilege escalation is a critical attack phase — detecting it at the network level provides early warning before compromise succeeds
2. Brute-force attacks against SSH remain the most common attack vector on Linux servers, making spike detection essential
3. Multi-port admin sweeps indicate an attacker probing for the weakest service, a pattern invisible to single-port detectors
4. Profile-gated activation ensures the detector does not generate noise in environments where admin-port traffic is routine
5. The dual sub-detector design provides complementary coverage of the two most common privilege escalation strategies
6. Time-windowed detection with configurable sizing allows defenders to balance sensitivity against their network's baseline
