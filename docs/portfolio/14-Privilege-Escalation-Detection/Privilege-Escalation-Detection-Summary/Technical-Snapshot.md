# Technical Snapshot: Privilege Escalation Detection

> The privilege escalation detector monitors network traffic against administrative ports, running two complementary sub-detectors: one that flags high-volume admin-port bursts (>= `PrivilegeSpikeMinAttempts` attempts in a sliding window) and one that flags multi-port admin sweeps (>= `PrivilegeSweepMinDistinctPorts` distinct admin ports in a sliding window). It implements `IDetector`, is cancellation-safe, and adapts its sensitivity through profile-based time windows and thresholds.

---

## Implementation Overview

The detector operates on the unified event stream produced by the log normalization pipeline. Each event carries a source IP, destination port, and timestamp. The detector first filters events targeting a curated set of admin ports (SSH, PostgreSQL, MySQL, RDP, VNC, and variants), groups by source IP, then runs two independent sub-detectors. `DetectAdminSpikes` uses a two-pointer sliding window to find brute-force-style bursts. `DetectAdminPortSweeps` uses a two-pointer sliding window with a `Dictionary<int, int>` to track distinct ports and find service enumeration across multiple admin ports.

---

## Key Metrics

| Metric | Value |
|---|---|
| Interfaces implemented | `IDetector` |
| Finding category | `PrivilegeEscalation` |
| Severities emitted | High (admin spikes), Medium (admin port sweeps) |
| Baseline admin ports | 8 (22, 2222, 2200, 22022, 3389, 5900, 5432, 3306) |
| Spike threshold | `PrivilegeSpikeMinAttempts` per window (profile-dependent: 5 Medium, 4 High) |
| Sweep threshold | `PrivilegeSweepMinDistinctPorts` per window (profile-dependent: 3 Medium, 2 High) |
| Time window range | 5–10 minutes (configurable) |
| Cancellation points | 1 (outer per-source loop) |
| Test coverage | 17 test methods |

---

## Why It Matters

- Privilege escalation is a critical phase in the attack lifecycle — attackers who gain admin access can establish persistence, exfiltrate data, and pivot laterally
- Brute-force attacks against SSH remain the most common network-based attack on Linux servers
- Multi-port admin sweeps indicate an attacker probing for the weakest administrative service to compromise
- Profile-gated activation ensures the detector runs only when appropriate for the analysis context
- Dual detection modes cover both single-port brute force and multi-port enumeration attack patterns

---

## Key Evidence

- [PrivilegeEscalationDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/PrivilegeEscalationDetector.cs) — detector implementation
- [AnalysisProfile.cs](../../../../VulcansTrace.Linux.Engine/AnalysisProfile.cs) — threshold configuration record
- [AnalysisProfileProvider.cs](../../../../VulcansTrace.Linux.Engine/Configuration/AnalysisProfileProvider.cs) — intensity presets
- [PrivilegeEscalationDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/PrivilegeEscalationDetectorTests.cs) — test suite

---

## Key Design Choices

- **Dual sub-detectors for complementary signals** — `DetectAdminSpikes` catches high-volume brute-force attacks on a single admin port (High severity), while `DetectAdminPortSweeps` catches quieter service enumeration across multiple admin ports (Medium severity). Together they cover the two most common privilege escalation vectors.

- **Baseline + profile admin port merging** — The detector defines a hardcoded baseline of 8 Linux-relevant admin ports and merges it with any `AdminPorts` supplied via the profile. This ensures the detector works out of the box while allowing environment-specific customization.

- **Sliding windows for both sub-detectors** — Both sub-detectors use two-pointer sliding windows with exact timestamp deltas (O(N)). Spikes count events in the window, while sweeps track distinct ports via a `Dictionary<int, int>`. Both use an `inFinding` state machine with peak tracking and post-loop finalization to emit one finding per contiguous burst.

- **Profile-gated activation** — The detector is entirely disabled under the Low intensity profile (`EnablePrivilegeEscalationDetection = false`). This prevents false positives in environments where admin-port traffic is routine and expected.

- **Burst-aware state machine for sweeps** — The sweep detector uses an `inFinding` state machine that finalizes one finding when the distinct-port count drops below threshold, then continues scanning. The sliding window naturally manages the dictionary contents. This enables detection of multiple separate sweeps from the same source while avoiding redundant alerts for the same contiguous burst.

---

## Security Takeaways

1. The detector addresses privilege escalation (MITRE TA0004) by monitoring admin-port access patterns at the network level
2. Dual detection modes cover both brute-force and service-enumeration attack strategies
3. The baseline admin port list targets the most commonly exploited Linux services — SSH, databases, RDP, and VNC
4. Profile-gated activation prevents noise in environments where admin-port traffic is expected
5. Two-pointer sliding-window sweep detection catches attackers probing multiple services that individually would not trigger the spike detector
