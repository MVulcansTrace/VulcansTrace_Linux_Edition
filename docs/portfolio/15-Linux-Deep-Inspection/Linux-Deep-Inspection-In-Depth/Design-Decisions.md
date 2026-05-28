# Design Decisions: Linux Deep Inspection

> The Linux Deep Inspection subsystem was designed with five independent detectors, each targeting a specific analytical dimension of Linux firewall metadata. Every design choice favors detector independence, deterministic output, and downstream correlation over monolithic multi-signal analysis.

---

## Decision 1 — Five Independent Detectors Instead of One Combined Analyzer

**Decision:** The subsystem is split into five separate `IDetector` implementations rather than a single multi-signal analyzer.

**Rationale:** Each detector targets a fundamentally different signal (flags, MACs, kernel modules, interfaces, packet sizes). Combining them would create a monolithic class with complex branching logic and mixed severity levels. Separate detectors are independently testable, independently configurable, and independently cancellable. Each can be enabled or disabled without affecting the others.

**Security Rationale:** Detector independence means a bug in one detector cannot crash or corrupt another. It also means findings from different detectors can be independently verified and triaged by analysts.

**Business Value:** Adding a new Linux-specific detector requires creating one new class — no changes to existing detectors. The `RiskEscalator` handles cross-detector correlation separately.

---

## Decision 2 — Linux-Specific Metadata via `LinuxSpecific` Dictionary

**Decision:** All five detectors consume metadata from the `LinuxSpecific` key-value dictionary on `UnifiedEvent` rather than adding typed properties to the core event record.

**Rationale:** Not all log formats provide flags, MAC addresses, interfaces, and packet sizes. Adding typed properties for Linux-specific fields to `UnifiedEvent` would pollute the core schema with platform-specific data that is irrelevant for Windows or generic log formats. The dictionary approach keeps the core schema clean while providing a flexible extension point.

**Security Rationale:** The `GetValueOrDefault` pattern ensures detectors degrade gracefully when metadata is missing — no exceptions, no null references, just empty findings.

**Business Value:** The same `UnifiedEvent` schema supports multiple log formats. Adding a new platform (e.g., pfSense, Cisco ASA) requires only a new normalizer that populates `LinuxSpecific` or a platform-specific dictionary.

---

## Decision 3 — Two-Phase Analysis in UnusualPacketSizeDetector

**Decision:** The packet size detector performs per-packet threshold checks immediately, followed by aggregate statistical analysis only when sufficient packets are available (configurable via `PacketSizeMinForAnalysis`, default 10).

**Rationale:** A single oversized packet (4000 bytes) is immediately suspicious and warrants alerting. But statistical patterns (consistency, variance) only become meaningful with sufficient sample size — 5 packets showing 80% consistency is noise, not a covert channel. The 10-packet gate prevents false positives from small samples.

**Security Rationale:** Clear-cut anomalies (size > `PacketSizeLargeThreshold`, size < `PacketSizeSmallThreshold`) are alerted immediately without waiting for aggregate data. Statistical anomalies are only reported when the evidence is strong enough to justify analyst attention.

**Business Value:** Analysts see actionable per-packet findings immediately, while aggregate findings provide additional context when sufficient data is available. This two-phase approach balances responsiveness against false-positive noise.

---

## Decision 4 — Keyword-Based Detection in KernelModuleDetector

**Decision:** The kernel module detector scans `RawLine` for string signatures rather than parsing structured data or requiring a specific log format schema.

**Rationale:** iptables log formats vary widely between distributions and configurations. Keyword matching is resilient to format variations — `"conntrack"` appears in the raw log line regardless of field ordering or delimiter choices. Structured parsing would require maintaining format-specific parsers for each iptables output variant.

**Security Rationale:** Broader matching reduces the risk of missing a module due to format differences. The trade-off is that common English words like `"limit"` or `"rate"` could theoretically match non-module content, but in the context of firewall log lines, these terms are strong module indicators.

**Business Value:** No format-specific parsing code to maintain. The detector works on any iptables/nftables log format that includes module names in the raw output.

---

## Decision 5 — Rapid-Switching Validation in InterfaceHoppingDetector

**Decision:** The interface hopping detector requires a confirmed rapid switch (interface change within the configured window) rather than flagging any source that uses multiple interfaces.

**Rationale:** Legitimate multi-homed hosts (gateways, routers, servers with bonded interfaces) routinely use multiple interfaces. Without the rapid-switching check, these hosts would produce constant false positives. The 5-minute window is short enough to catch active reconnaissance (an attacker probing eth0, then immediately eth1) while filtering out stable configurations.

**Security Rationale:** The rapid-switch validation is a false-positive filter, not a detection gap. Any attacker pivoting between segments will produce rapid interface changes during active probing.

**Business Value:** Reduced false-positive rate means analysts can trust InterfaceHopping findings without manual whitelisting of known multi-homed hosts.

---

## Decision 6 — Downstream Correlation via RiskEscalator

**Decision:** All cross-detector correlation happens in `RiskEscalator`, not inside individual detectors. The escalator promotes FlagAnomaly+PortScan and MacSpoofing+InterfaceHopping to Critical severity.

**Rationale:** Embedding correlation logic inside detectors creates coupling — a detector that checks for MAC spoofing would need to know about interface hopping findings. The `RiskEscalator` operates on the finding stream after all detectors have run, grouping by `SourceHost` and checking for category combinations. This keeps each detector focused on its single analytical dimension.

**Security Rationale:** The correlation rules are explicit and auditable: FlagAnomaly+PortScan indicates advanced evasion combined with reconnaissance; MacSpoofing+InterfaceHopping indicates coordinated L2/L3 attack activity.

**Business Value:** New correlation rules are added to `RiskEscalator` without modifying any detector. This is a single point of change for escalation policy.

---

## Summary

| Decision | Trade-off | Benefit |
|---|---|---|
| Five independent detectors | More classes to maintain | Independent testing, configuration, and cancellation |
| `LinuxSpecific` dictionary | Stringly-typed metadata access | Clean core schema, flexible extension point |
| Two-phase packet size analysis | Aggregate findings delayed until sufficient packets (configurable) | Immediate per-packet alerts, reduced statistical noise |
| Keyword-based module detection | Potential false matches on common words | Format-resilient, no format-specific parsers |
| Rapid-switching validation | Misses slow interface switching | Filters legitimate multi-homed hosts |
| Downstream correlation via `RiskEscalator` | Correlation is separate from detection | Decoupled detectors, auditable escalation rules |

---

## Security Takeaways

1. Detector independence ensures that a bug or failure in one detector does not affect the others — partial results are still reliable
2. The `LinuxSpecific` dictionary pattern provides a clean extension point for future platform-specific detectors without schema changes
3. The two-phase packet size analysis balances immediate alerting against statistical rigor
4. Keyword-based kernel module detection trades specificity for resilience, which is appropriate for posture assessment
5. The `RiskEscalator` provides a single, auditable location for all cross-detector correlation rules
