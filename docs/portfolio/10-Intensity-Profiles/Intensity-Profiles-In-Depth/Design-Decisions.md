# Intensity Profiles — Design Decisions

> The profile subsystem prioritizes coherence over flexibility — three tested presets with an escape hatch (override) over unlimited per-knob configuration.

---

## Decision 1: Sealed Record Over Mutable Class

**Decision:** `AnalysisProfile` is a `sealed record` with `init`-only properties.

**Rationale:** Detectors run concurrently within an analysis pass. If the profile were mutable, one detector could accidentally modify thresholds that another detector is reading. The sealed record prevents this class of bug at compile time.

**Security Rationale:** Detection thresholds directly control what is and is not flagged as a threat. Accidental mutation could silently disable detection or produce inconsistent results across detectors.

**Business Value:** No defensive copying, no locking, no "who mutated my config" debugging sessions.

---

## Decision 2: Switch Expression Over If/Else Chain

**Decision:** `AnalysisProfileProvider.GetProfile` uses a C# switch expression.

**Rationale:** The compiler enforces exhaustive matching. If a new `IntensityLevel` value is added, every switch expression that consumes it must be updated or the code will not compile. An if/else chain would silently fall through to the `_` default.

**Security Rationale:** A missing intensity level handler could return `null` or throw at runtime when an operator selects the new level — a failure mode that is invisible until production.

**Business Value:** Compile-time safety for configuration correctness; refactoring confidence when adding new levels.

---

## Decision 3: Shared Policy Lists Across All Profiles

**Decision:** AdminPorts and DisallowedOutboundPorts are identical in all three profiles.

**Rationale:** These represent organizational security policies, not sensitivity levels. SSH (22) is an admin port regardless of whether the analysis is Low, Medium, or High. Similarly, outbound FTP (21) and Telnet (23) should always be flagged.

**Security Rationale:** If policy lists varied by profile, an operator running a Low-intensity analysis would miss policy violations that a High-intensity analysis catches — not because the violations are below threshold, but because the policy itself is different. This is a policy inconsistency, not a sensitivity difference.

**Business Value:** Consistent policy enforcement regardless of analysis context; no "wrong profile" surprises.

---

## Decision 4: Enable Flags Over Infinite Thresholds

**Decision:** Disabling a detector uses a boolean flag (e.g., `EnableNovelty = false`) rather than setting its threshold to an unachievable value.

**Rationale:** An enable flag is explicit and self-documenting. Setting `BeaconMinEvents = int.MaxValue` would technically disable beaconing detection, but it's not clear from the threshold alone whether the intent is "disabled" or "very high threshold." The flag communicates intent.

**Security Rationale:** Guard clauses in detectors check enable flags first and return immediately — zero allocation, zero computation. A disabled detector with a high threshold would still allocate data structures and iterate events before determining nothing qualifies.

**Business Value:** Clear enable/disable semantics; faster execution for disabled detectors; easier audit trail.

---

## Decision 5: MinSeverityToShow as Output Filter

**Decision:** The profile includes `MinSeverityToShow` that filters findings after detection and escalation.

**Rationale:** This decouples detection sensitivity from output visibility. The Low profile runs detectors (most are enabled) but only shows High-severity findings. This means the risk escalation engine still processes all findings — cross-correlations and escalation rules still fire — but the analyst only sees the most actionable results.

**Security Rationale:** A finding that is filtered from output still contributes to risk escalation. A Medium-severity port scan finding in the Low profile can still combine with other findings to produce an escalated High-severity result that passes the filter.

**Business Value:** Analysts see fewer findings in low-sensitivity mode without losing escalation fidelity.

---

## Decision 6: Override Profile Parameter

**Decision:** `SentryAnalyzer.Analyze` accepts an optional `overrideProfile` parameter.

**Rationale:** The three presets cover most use cases, but some analyses require specialized thresholds — for example, investigating a known APT with unusually low beaconing intervals, or analyzing a high-traffic server that would overwhelm standard flood thresholds.

**Security Rationale:** Without the override, operators would need to modify `AnalysisProfileProvider` source code for specialized analysis — a risky change that affects all users. The override isolates custom configuration to a single analysis run.

**Business Value:** Extensibility without forking; custom analysis is first-class via the API.

---

## Summary

| Decision | Trade-off | Security Outcome |
|---|---|---|
| Sealed record | Cannot hot-swap thresholds mid-run | No concurrent mutation bugs |
| Switch expression | Must update all arms for new levels | Compile-time exhaustiveness |
| Shared policy lists | Cannot tune policy per profile | Consistent enforcement |
| Enable flags over thresholds | More properties to maintain | Explicit, zero-cost disable |
| MinSeverityToShow filter | Some findings are computed but hidden | Escalation fidelity preserved |
| Override parameter | Bypasses factory validation | Escape hatch for specialized analysis |
