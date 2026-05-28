# Policy Violation Detection — Design Decisions

> The policy violation detector proves that the most effective security tooling is often the simplest — a grouped filter that catches every violating event group, with configurable thresholds and minimal overhead.

---

## Decision 1: Stateless Per-Event Evaluation

**Decision:** Evaluate each event with three independent filters, then group matching events by `(SourceIP, DstPort)` for aggregated reporting.

**Rationale:** Policy violations are binary — either a connection uses a disallowed port or it doesn't. There is no temporal component or sliding window to manage. However, aggregating violations by `(SourceIP, DstPort)` produces richer findings: connection counts, distinct destination tallies, and time ranges. A per-event finding would flood the alert stream with redundant information when the same host repeatedly violates the same policy.

**Security Rationale:** Grouping preserves complete coverage — every matching event is captured in the group's counts — while producing actionable, aggregated findings. A configurable `PolicyViolationMinEvents` threshold (default 1) allows environments to require multiple violations before alerting, filtering one-time misconfigurations. Note that downstream pipeline stages (severity filtering via `MinSeverityToShow`, risk escalation) can still affect which findings reach the final user-visible output.

**Business Value:** Grouped findings reduce alert fatigue while maintaining forensic detail. The detector is gated by `profile.EnablePolicy` and returns immediately when disabled, keeping the activation cost near zero.

---

## Decision 2: One Finding Per Group

**Decision:** Emit one finding per `(SourceIP, DstPort)` group, aggregating all matching events into a single finding with counts and time ranges.

**Rationale:** A per-event finding would flood the alert stream when the same host repeatedly connects to the same external destination on a disallowed port. The grouped finding captures all the necessary forensic detail — total connection count, number of distinct destinations, and the full time span — in a single actionable alert. When a host contacts multiple distinct external IPs on the same disallowed port, the finding still reports the full scope (`"multiple hosts:{port}"`).

**Security Rationale:** Aggregated findings reduce alert fatigue while preserving complete forensic context. Investigators can see the total scope of the violation without cross-referencing multiple individual alerts. The `Details` field explicitly states the event count and distinct destination count.

**Business Value:** Supports compliance objectives for violation logging (PCI DSS, HIPAA, SOC 2) by providing both aggregated summaries and granular counts in a single finding. (Compliance frameworks require broader controls beyond any single detector.)

---

## Decision 3: Internal-to-External Scope Only

**Decision:** Only flag connections where the source is internal and the destination is external.

**Rationale:** Outbound policy violations are the security concern — internal hosts sending data to external destinations on prohibited protocols. Inbound connections on these ports (e.g., someone trying to connect to an internal Telnet server) are a different problem handled by different controls. Internal-to-internal connections on disallowed ports are also out of scope — they're not exfiltration vectors.

**Security Rationale:** Focuses the detector on the data exfiltration use case. Outbound connections on FTP/Telnet/SMB are strong indicators that warrant investigation — they may signal compromise, misconfiguration, or malware activity. Findings are emitted at `Severity.High` but can be escalated to `Critical` by the `RiskEscalator` when correlated threats (e.g., beaconing + lateral movement) are detected for the same host.

**Business Value:** Reduces noise by excluding inbound and internal-to-internal connections that don't represent exfiltration risk.

---

## Decision 4: Profile-Driven Port List

**Decision:** Define disallowed ports in `AnalysisProfile` rather than hardcoding.

**Rationale:** Different environments have different prohibited protocols. A legacy manufacturing network might need FTP, while a modern SaaS company would never allow it. The profile allows per-environment customization. All three default profiles (Low, Medium, High) ship with the same disallowed ports — `[21, 23, 445]` (FTP, Telnet, SMB) — but custom profiles can define any port list.

**Security Rationale:** Hardcoded port lists require code changes to adapt — a slow process. Profile-driven configuration allows rapid response to new policy requirements (e.g., "block port 23 on all servers effective immediately").

**Business Value:** One detector serves all environments without code modification.

---

## Decision 5: Null-Coalescing Port Default

**Decision:** Use `profile.DisallowedOutboundPorts ?? Array.Empty<int>()` to handle null profiles gracefully.

**Rationale:** If the profile doesn't define disallowed ports, the detector should silently produce no findings rather than throwing a `NullReferenceException`. An empty disallowed set means no ports are prohibited — a valid configuration.

**Security Rationale:** Fail-safe behavior — the detector defaults to permissive (no violations) rather than restrictive (everything is a violation) when misconfigured.

**Business Value:** Graceful degradation prevents crashes on misconfigured deployments.

---

## Summary

| Decision | Trade-off | Security Outcome |
|---|---|---|
| Grouped evaluation | Aggregated per (SourceIP, DstPort) | Complete coverage with reduced alert volume¹ |
| One finding per group | Slightly less granular than per-event | Full aggregated audit trail for compliance |
| Internal-to-external only | Misses inbound violations | Focused on exfiltration detection |
| Profile-driven port list | Requires configuration | Adaptable to any environment |
| Null-coalescing default | Silently permissive on misconfig | Fail-safe, no crashes |

¹ Downstream pipeline stages — `RiskEscalator` severity promotion and `MinSeverityToShow` filtering — can affect which findings appear in the final user-visible output.
