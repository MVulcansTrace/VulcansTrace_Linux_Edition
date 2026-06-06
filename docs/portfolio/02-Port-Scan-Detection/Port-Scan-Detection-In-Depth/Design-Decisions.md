# Design Decisions: Port Scan Detection

> The port scan detector was designed to balance detection accuracy against computational cost on real-world iptables logs, where a single source can generate tens of thousands of events. Every design choice favors deterministic, analyst-transparent behavior over probabilistic scoring.

---

## Decision 1 — Sliding Time Windows

**Decision:** Time windows are evaluated with start/end pointers over each source's timestamp-ordered events.

**Rationale:** A two-pointer sliding window avoids fixed-boundary false negatives without comparing every event pair. The active window is maintained in O(n) after the per-source timestamp sort, using a dictionary of destination-port counts.

**Security Rationale:** A scan crossing a 5-minute clock boundary is still evaluated as one continuous burst when the events fall within `PortScanWindowMinutes`. Output remains deterministic for the same input log.

**Business Value:** O(n) windowing keeps the detector performant on large logs without requiring fixed bucket alignment or batch sizing.

---

## Decision 2 — Distinct Destination-Port Counting

**Decision:** The detector counts unique destination ports rather than total events or destination IP:port tuples.

**Rationale:** Raw event counts are inflated by retries, retransmissions, and long-lived connections. Distinct destination-port counting aligns with the `PortScanMinPorts` configuration and UI label. It detects service-enumeration scans while avoiding false positives where one destination port is contacted across many hosts.

**Security Rationale:** This metric directly measures reconnaissance breadth. An attacker learning about 15 different services is more dangerous than one generating 15 retries to the same port.

**Business Value:** Lower false-positive rate compared to event-volume or destination-pair counting, reducing alert fatigue for security teams.

---

## Decision 3 — Pre-Window Gate

**Decision:** Before entering the sliding-window pass, the detector counts distinct destination ports across the (potentially truncated) events for a source and skips the source entirely if the count is below `PortScanMinPorts`.

**Rationale:** Window analysis is more expensive than a single `Distinct().Count()` pass. Sources that contacted fewer distinct destination ports than the threshold across all analyzed events cannot possibly exceed it in any subset window. Skipping them avoids wasted computation.

**Security Rationale:** No detection coverage is lost — if a source never reaches the threshold across its available events, it cannot reach it in any individual window.

**Business Value:** Significant performance improvement on logs where most sources are benign, which is the common case.

---

## Decision 4 — Truncation via `PortScanMaxEntriesPerSource` with Warnings

**Decision:** An optional cap limits the number of events analyzed per source. When hit, the detector emits a warning in `DetectionResult.Warnings` rather than failing silently.

**Rationale:** A compromised host under sustained attack can generate millions of log entries. Without a cap, the detector's memory and CPU usage would scale linearly with the noisiest source. The truncation approach bounds resource usage while preserving the latest events, which are typically most relevant for the current analysis pass.

**Security Rationale:** Silent data loss would undermine analyst confidence. Warnings ensure the analyst knows when findings may be incomplete for a source.

**Business Value:** Predictable memory usage regardless of log volume, without requiring external rate-limiting or sampling infrastructure.

---

## Decision 5 — Fixed Medium Severity with Downstream Escalation

**Decision:** Port scan findings always start at Medium severity. Escalation to Critical happens downstream in the `RiskEscalator` when a source host produces time-correlated port scan and flag anomaly findings. When this correlation is detected, only the participating PortScan and FlagAnomaly findings are escalated to Critical, and detection confidence is recalculated via `FindingConfidenceCalculator`.

**Rationale:** A port scan in isolation is reconnaissance, not exploitation. Medium severity reflects the actual threat level. However, port scanning combined with TCP flag manipulation (SYN/FIN, XMAS scans) indicates advanced evasion techniques, warranting Critical severity.

**Security Rationale:** Separating detection from correlation allows each detector to focus on a single signal. The `RiskEscalator` provides the holistic view.

**Business Value:** Analysts can triage findings using the severity gradient — standalone scans at Medium, correlated threats at Critical — without custom scoring logic in each detector. On the Low profile, the severity floor (`MinSeverityToShow = High`) filters standalone Medium-severity port scan findings; only correlated findings escalated to Critical are visible.

---

## Decision 6 — Profile-Based Thresholds (Low/Medium/High)

**Decision:** Detection thresholds (`PortScanMinPorts`, `PortScanWindowMinutes`) are stored in `AnalysisProfile` and configured per intensity level via `AnalysisProfileProvider`, not hardcoded in the detector.

**Rationale:** Different network environments have different baselines. A busy data center may see 30 distinct connections per source in normal operation, while a small office network would not. Profile-based thresholds allow per-deployment tuning without code changes.

**Security Rationale:** Operators can increase sensitivity during incident response (switch to High profile) without redeploying or rebuilding the tool.

**Business Value:** A single codebase supports diverse deployment environments through configuration, not branching.

---

## Summary

| Decision | Trade-off | Benefit |
|---|---|---|
| Sliding windows | Slightly more state than fixed buckets | Avoids fixed-boundary false negatives while staying O(n) after sort |
| Distinct destination-port counting | Does not detect same-port sweeps as port scans | Lower false-positive rate, matches `PortScanMinPorts` semantics |
| Pre-window gate | None — pure optimization | Avoids wasted computation on benign sources |
| Truncation with warnings | Latest events may not represent full scan | Bounded memory, analyst transparency |
| Fixed Medium + downstream escalation | Requires RiskEscalator for Critical severity | Clean separation of detection and correlation |
| Profile-based thresholds | Three profiles may not cover all environments | Per-deployment tuning without code changes |

---

## Security Takeaways

1. Every design decision prioritizes analyst transparency — warnings on truncation, deterministic sliding windows, and clear finding details
2. The pre-window gate is a zero-risk optimization that never sacrifices detection coverage
3. Separating detection severity from correlation severity allows the detector to remain simple while the system provides nuanced risk assessment
4. Profile-based thresholds enable operational flexibility without increasing code complexity
5. The truncation-warning pattern is a generalizable approach for any detector that might process unbounded input
