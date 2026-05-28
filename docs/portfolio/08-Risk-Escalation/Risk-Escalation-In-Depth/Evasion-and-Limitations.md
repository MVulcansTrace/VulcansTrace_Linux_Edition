# Risk Escalation — Evasion and Limitations

Known weaknesses, blind spots, and the improvement roadmap for the risk escalation subsystem.

---

## Known Limitations

### Time-Range Correlation Limitations

The escalator checks whether findings from the two categories in a rule have time ranges within a 24-hour window (`AreTimeRangesCorrelated`). However, this is a gap-based check, not an overlap check — two findings can trigger escalation even if they do not temporally overlap (e.g., one ends at 02:00 and the other starts at 25:00, with a 23-hour gap).

**Impact**: Potential false-positive escalations when correlated behaviors are temporally disjoint but within the 24-hour window. Conversely, a 25-hour gap prevents escalation even when the behaviors are clearly related.

**Mitigation**: The 24-hour threshold (`maxGapHours = 24.0`) is a fixed constant. Future versions could make this configurable per rule or profile.

---

### No Cross-Host Correlation

Correlation is strictly host-scoped. An attacker controlling multiple hosts (e.g., a botnet) would produce independent finding sets per host, and the escalator would not detect the campaign-level pattern.

**Impact**: Distributed attacks and coordinated campaigns are not escalated.

**Mitigation**: A future campaign-correlation layer could group findings by destination IP (shared C2 infrastructure), time window, or behavioral fingerprint. This would be a separate subsystem, not a change to `RiskEscalator`.

---

### Fixed Rule Set

The three correlation rules are hardcoded. Adding new rules requires modifying `RiskEscalator.cs`, updating tests, and rebuilding.

**Impact**: Cannot add correlation rules at deployment time or in response to emerging threats without a code change.

**Mitigation**: The rule evaluation is simple enough that a rule-table approach (list of category pairs) could be introduced without changing the algorithm. This would allow rules to be defined in configuration.

---

### Binary Escalation Only

Escalation is all-or-nothing: a finding either stays at its original severity or is promoted to Critical. There is no intermediate escalation (e.g., Medium to High) or multi-level escalation.

**Impact**: Some correlated findings may be over-escalated (a Low-severity finding promoted directly to Critical) or under-escalated (a finding that warrants High but not Critical has no escalation path).

**Mitigation**: A severity-boost table (e.g., +1 level for partial correlation, +2 for full correlation) could be added as a future enhancement.

---

### Fixed 24-Hour Time-Range Threshold

The `maxGapHours = 24.0` constant is hardcoded and applies uniformly to all three correlation rules. An attack spread across a 25-hour window (e.g., beaconing at midnight, lateral movement the next day at 01:00) will not trigger escalation even though the behaviors are clearly related.

**Impact**: Slightly delayed or time-stretched multi-stage attacks may escape escalation.

**Mitigation**: Make `maxGapHours` configurable per rule or per profile. Some rules (e.g., Beaconing + LateralMovement) might warrant a 48-hour or 72-hour window.

---

## Evasion Techniques

### Category Fragmentation Across Hosts

An attacker who distributes Beaconing traffic across one source IP and LateralMovement traffic across a different source IP will avoid triggering the host-scoped correlation rules. Each host would only have one category of finding.

**Detection gap**: No campaign-level correlation.

**Partial mitigation**: The individual findings still trigger their respective detectors at High severity. The escalation layer does not suppress non-correlated findings — it only promotes correlated ones.

### Category Avoidance

If an attacker can avoid triggering a second detector category (e.g., performing lateral movement without beaconing, or using techniques that the beaconing detector does not recognize as periodic), the correlation rules will not fire.

**Detection gap**: Single-category attacks are not escalated.

**Partial mitigation**: The individual finding is still produced at its detector-assigned severity. Escalation is a bonus for multi-category correlation, not a replacement for single-detector detection.

### Timing Manipulation

An attacker aware of the 24-hour threshold could deliberately spread correlated behaviors across a gap just larger than 24 hours (e.g., beacon at 00:00, then move laterally at 00:01 the following day) to avoid triggering the time-range correlation check.

**Detection gap**: Multi-stage attacks with deliberately stretched timelines may escape escalation.

**Partial mitigation**: Downstream triage tools can inspect the `TimeRangeStart` and `TimeRangeEnd` fields to assess temporal relevance. A longer or configurable threshold would reduce this gap.

### Source IP Spoofing

If an attacker spoofs source IP addresses, findings attributed to different hosts may actually originate from the same attacker, and the host-scoped correlation would not fire.

**Detection gap**: Attribution is based on reported source IP, which can be spoofed in network logs.

**Partial mitigation**: The `MacSpoofing` detector and `InterfaceHopping` detector can identify hosts that are manipulating their network identity, and the MacSpoofing + InterfaceHopping correlation rule can escalate based on this evidence.

---

## Improvement Roadmap

| Priority | Improvement | Effort |
|----------|------------|--------|
| High | Configurable `maxGapHours` per correlation rule | Small — change constant to profile-driven value |
| Medium | Configurable rule table (category pairs in configuration) | Medium — refactor rule evaluation to iterate over a rule list |
| Medium | Cross-host campaign correlation | Large — new subsystem |
| Low | Multi-level severity escalation (+1, +2) | Small — add severity boost table |
| Low | Temporal overlap check (stricter than gap-based) | Small — require actual time-range overlap, not just gap ≤ 24h |

---

## Security Takeaways

- The three correlation rules cover well-documented attacker patterns but are not exhaustive — attackers who avoid triggering multiple categories on the same host will not be escalated
- Temporal correlation is the highest-priority improvement because it would eliminate false-positive escalations from temporally disjoint findings
- Cross-host campaign correlation is a fundamentally different problem that should be addressed by a separate subsystem, not by expanding the current host-scoped escalator
- The evasion techniques listed here exploit limitations in scope (host-scoping) and dimensionality (no temporal check), not weaknesses in the correlation logic itself — the rules are sound for the dimensions they cover
