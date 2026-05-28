# Risk Escalation — Why This Matters

The security reasoning behind host-scoped threat correlation and why isolated detector findings are not enough.

---

## The Problem

Network intrusion detection systems typically produce findings in isolation: a port scan detector fires on reconnaissance, a beaconing detector fires on periodic callbacks, and a MAC spoofing detector fires on identity manipulation. Each finding carries its own severity based on the confidence of that single detector.

The problem is that attackers do not operate in one dimension. A compromised Linux server will often exhibit multiple behaviors simultaneously — calling home to a C2 server while probing internal hosts, or manipulating TCP flags while scanning ports to evade IDS rules. When these findings are viewed independently, each one may only warrant Medium or High severity. When they are correlated on the same host, the combined picture demands Critical severity and immediate investigation.

Without correlation, a SOC analyst triaging by severity would de-prioritize the individual findings and miss the full scope of the compromise.

---

## Elevator Pitch

VulcansTrace solves this by running all detectors independently and then applying host-scoped correlation rules that escalate findings to Critical when specific category combinations appear on the same source IP. The three rules — Beaconing + LateralMovement, FlagAnomaly + PortScan, and MacSpoofing + InterfaceHopping — each represent a well-documented attacker behavior pattern. The escalation is immutable (new record copies via `with`), fault-isolated (per-detector try/catch), and always applied before the severity filter so that Critical findings are never suppressed by the intensity profile.

---

## Operational Benefits

### Reduced Alert Fatigue

Without escalation, an analyst sees a Beaconing finding at Medium and a LateralMovement finding at High on the same host and must manually correlate them. With escalation, both participating findings are promoted to Critical automatically, and the analyst sees one high-priority host instead of two disconnected alerts.

### Higher-Confidence Triage

Correlation across categories provides stronger evidence than any single detector. A host that is both beaconing and moving laterally is almost certainly compromised — not a false positive from noisy network telemetry.

### No Data Loss

Escalation creates new `Finding` record copies rather than mutating originals. The original severity, category, and all metadata are preserved. An analyst can inspect both the pre-escalation and post-escalation state.

### Fault Tolerance

Each detector in the three-layer pipeline is wrapped in its own try/catch. If the FlagAnomaly detector crashes, the PortScan detector still runs, and the MacSpoofing + InterfaceHopping rule can still fire. A failing detector produces a warning in the output rather than halting the entire analysis.

### Deterministic Output

The correlation rules are pure boolean checks against a set of category strings. There is no machine learning, no statistical threshold, and no nondeterministic behavior. Given the same input findings, the escalator always produces the same output. This is essential for reproducible forensic analysis.

---

## What This Subsystem Does Not Do

- It does not weight correlation rules differently (all rules escalate to Critical)
- It does not suppress or deduplicate findings (escalation only upgrades severity)
- It does not perform cross-host correlation (each host is evaluated independently)
- Its time-range correlation uses a fixed 24-hour gap threshold, not configurable per rule or profile

These limitations are discussed in detail in [Evasion and Limitations](./Evasion-and-Limitations.md).

---

## Security Takeaways

- Isolated detector findings understate the true risk of a compromised host because attackers exhibit multiple behaviors simultaneously
- Host-scoped correlation turns disconnected Medium and High findings into actionable Critical alerts
- Immutable escalation ensures the original detector output is preserved for forensic review
- Fault isolation guarantees that a single detector failure cannot suppress escalation of findings from other healthy detectors
- The correlation rules are deterministic and auditable, which is critical for forensic evidence that may be reviewed in incident response or legal proceedings
