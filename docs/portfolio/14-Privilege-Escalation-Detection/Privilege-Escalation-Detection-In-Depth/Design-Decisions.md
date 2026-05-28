# Design Decisions: Privilege Escalation Detection

> The privilege escalation detector was designed to identify two complementary attack patterns — brute-force admin-port bursts and multi-port service enumeration — using independent sub-detectors within a single `IDetector` implementation. Every design choice favors clear signal separation, analyst transparency, and profile-based tunability.

---

## Decision 1 — Dual Sub-Detectors Instead of a Single Unified Check

**Decision:** The detector contains two independent sub-detectors (`DetectAdminSpikes` and `DetectAdminPortSweeps`) rather than a single combined analysis.

**Rationale:** Brute-force attacks and service enumeration are fundamentally different signals. A brute-force attack produces high volume against one port; a sweep produces low volume against many ports. A single threshold cannot effectively capture both patterns — a 50-attempt SSH brute-force and a 3-port sweep require different counting strategies.

**Security Rationale:** Separating the signals allows each sub-detector to use the optimal counting approach for its pattern — event counts for spikes and distinct-port tracking for sweeps — while both share the same sliding-window strategy. Each sub-detector emits findings at the appropriate severity level.

**Business Value:** Analysts receive specific, actionable alerts: High-severity brute-force warnings demand immediate response, while Medium-severity sweep findings indicate reconnaissance that warrants investigation.

---

## Decision 2 — Baseline + Profile Admin Port Merging

**Decision:** The detector defines a hardcoded baseline of 8 Linux-relevant admin ports and merges it with any `AdminPorts` supplied via the `AnalysisProfile`.

**Rationale:** Different environments expose different admin services. The baseline covers the most commonly targeted ports on Linux servers (SSH variants, RDP, VNC, PostgreSQL, MySQL). The profile-supplied ports allow environments running services on non-standard ports (e.g., SSH on 2222 or a custom database port) to extend detection without modifying detector code.

**Security Rationale:** Hardcoded baselines ensure the detector is effective immediately without configuration, while profile merging allows operators to adapt to their specific attack surface. The `Distinct()` call prevents duplicate ports from inflating the set.

**Business Value:** Zero-configuration deployment for standard Linux environments, with straightforward customization for non-standard setups.

---

## Decision 3 — Sliding Windows for Both Sub-Detectors

**Decision:** Both `DetectAdminSpikes` and `DetectAdminPortSweeps` use sliding time windows with exact timestamp deltas. The spike detector counts events in the window, while the sweep detector tracks distinct ports via a dictionary.

**Rationale:** Both sub-detectors use two-pointer sliding windows for consistency and to avoid quantization boundary artifacts. The spike detector counts total events within the time span. The sweep detector tracks distinct ports within the same time span using a dictionary. Both run in O(n) per source.

**Security Rationale:** Sliding windows for both sub-detectors ensure patterns are detected regardless of when events fall relative to arbitrary window boundaries, avoiding the split-window problem that quantized windows create.

**Business Value:** Both sub-detectors use the same windowing strategy, reducing cognitive load for maintainers while each still uses the optimal counting approach for its signal type.

---

## Decision 4 — Profile-Gated Activation

**Decision:** The detector is entirely disabled under the Low intensity profile (`EnablePrivilegeEscalationDetection = false`).

**Rationale:** In environments where admin-port traffic is routine (data centers, development servers, jump boxes), the detector would generate excessive false positives. The Low profile is designed for conservative, high-confidence analysis, and admin-port monitoring does not fit that profile.

**Security Rationale:** Running the detector where it produces mostly false positives degrades analyst trust and wastes triage time. Disabling it under Low ensures findings from Medium and High profiles carry higher confidence.

**Business Value:** Operators can choose the appropriate sensitivity level for their environment without modifying individual detector settings.

---

## Decision 5 — Differentiated Severity Levels

**Decision:** Admin spikes emit High severity; admin port sweeps emit Medium severity.

**Rationale:** A brute-force attack against an admin service is an immediate threat — if successful, the attacker gains administrative access. Service enumeration is reconnaissance — the attacker is probing for weaknesses but has not yet compromised anything. The severity levels reflect the actual threat stage.

**Security Rationale:** Severity differentiation helps analysts prioritize response. High-severity brute-force findings should be investigated immediately, while Medium-severity sweep findings can be correlated with other signals for a more complete picture.

**Business Value:** Security teams can route High-severity findings to on-call responders and batch Medium-severity findings for daily review, optimizing resource allocation.

---

## Decision 6 — Burst-Aware Sweep Emission

**Decision:** The sweep detector uses a burst-aware `inFinding` state machine that tracks peak distinct ports within a contiguous above-threshold window, emits one finding per burst, and continues scanning for additional separate sweeps.

**Rationale:** A single contiguous sweep produces one finding with the peak distinct-port count. If the attacker pauses and resumes later, the distinct-port count drops below threshold, the first finding is finalized with its peak value, and scanning continues to detect the next burst.

**Security Rationale:** One finding per contiguous burst prevents duplicate alerts for the same sweep while still catching separate sweep episodes from the same source. The peak distinct-port count ensures the finding captures the maximum breadth of the enumeration.

**Business Value:** Alert fatigue reduction — one clear finding per sweep event instead of potentially dozens of overlapping alerts.

---

## Summary

| Decision | Trade-off | Benefit |
|---|---|---|
| Dual sub-detectors | More code than a single check | Clear signal separation, appropriate severity per pattern |
| Baseline + profile merging | Slightly larger port set than hardcoded alone | Zero-config deployment with extensibility |
| Sliding windows for both sub-detectors | Same windowing strategy, different counting approaches | Optimal algorithm per signal type |
| Profile-gated activation | No detection under Low profile | Eliminates false positives in admin-heavy environments |
| Differentiated severity | Two severity levels to manage | Prioritized analyst response |
| Burst-aware sweep emission | One finding per contiguous burst | Reduced alert fatigue, clearer signal |

---

## Security Takeaways

1. Dual sub-detectors provide comprehensive coverage of both brute-force and enumeration attack strategies
2. The baseline admin port list ensures immediate detection capability without requiring configuration
3. Profile-gated activation prevents noise in environments where admin-port traffic is expected and legitimate
4. Differentiated severity levels reflect the actual threat stage — immediate danger vs. reconnaissance
5. The sweep single-report pattern balances thoroughness against alert fatigue, delivering actionable findings
6. Every design decision prioritizes analyst transparency and operational tunability over detection complexity
