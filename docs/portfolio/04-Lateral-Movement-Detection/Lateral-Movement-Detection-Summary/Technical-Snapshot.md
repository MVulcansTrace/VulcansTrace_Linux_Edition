# Lateral Movement Detection — Technical Snapshot

> The lateral movement detector catches the critical post-exploitation phase where an attacker pivots through an internal network. By filtering for internal-to-internal traffic on administrative ports (SMB/445, RDP/3389, SSH/22) and applying a two-pointer sliding window over distinct destination hosts, the detector transforms raw firewall logs into actionable high-severity findings — all in 120 lines of production C# with 687 lines of dedicated test coverage.
>
> This subsystem demonstrates skills in **streaming time-series analysis**, **threshold-based anomaly detection**, **internal network classification (RFC 1918 and IPv6 private ranges)**, and **profile-driven configuration** — all core competencies for network security tooling.

---

## Implementation Overview

The detector receives a pre-normalized `UnifiedEvent` list, filters to internal-to-internal flows on admin ports, groups by source IP, and runs a two-pointer sliding window counting distinct destination IPs within `LateralWindowMinutes`. When the distinct host count reaches `LateralMinHosts`, a finding is created; as long as the count stays above threshold, the finding is extended. When the count drops below threshold, the finding is finalized. Separate time-separated bursts from the same source can produce separate findings.

---

## Key Metrics

| Metric | Value |
|---|---|
| Production code | 120 lines |
| Test code | 687 lines |
| Test-to-code ratio | 5.7 : 1 |
| Time complexity | O(n log n) per source — sorting dominates; sliding window scan is O(n) |
| Space complexity | O(n) per source |
| Configurable thresholds | 3 (Low / Medium / High) |
| Admin ports monitored | 3 (445, 3389, 22) |
| MITRE ATT&CK coverage | T1021, T1047, T1059, TA0008 |

---

## Why It Matters

- Lateral movement is a **mid-chain phase** of most advanced attacks — after initial compromise and privilege escalation, before data exfiltration
- Detection at this stage **breaks the kill chain** before attackers reach high-value assets
- Admin-port-only filtering maximizes signal-to-noise ratio by ignoring benign internal traffic
- The sliding window approach handles **realistic attack timing** — attackers don't move instantly

---

## Key Evidence

- [LateralMovementDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/LateralMovementDetector.cs) — core detection logic with two-pointer window
- [IpClassification.cs](../../../../VulcansTrace.Linux.Engine/Net/IpClassification.cs) — internal/external IP classification
- [AnalysisProfile.cs](../../../../VulcansTrace.Linux.Engine/AnalysisProfile.cs) — threshold configuration
- [LateralMovementDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/Baseline/LateralMovementDetectorTests.cs) — comprehensive test suite

---

## Key Design Choices

1. **Two-pointer sliding window** over naive counting — correctly handles temporal clustering without double-counting expired events
2. **Distinct destination IP counting** inside the window — prevents a single chatty host from triggering the detector
3. **Burst-aware finding emission** — one finding per contiguous above-threshold burst; separate time-separated bursts from the same source produce separate findings
4. **Profile-driven thresholds** — one configuration change adjusts sensitivity without code modification
5. **HashSet-based admin port lookup** — O(1) port membership check during the hot filter path
