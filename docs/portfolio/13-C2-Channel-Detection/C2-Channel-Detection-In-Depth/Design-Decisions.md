# Design Decisions

> **Every design choice in this detector has a statistical rationale, a performance consideration, and an operational impact.**

---

## Decision 1: Tolerance-Based Clustering Instead of Standard Deviation

**Decision:** Cluster deltas using a greedy sliding window on sorted values (grouping consecutive deltas within `tolerance * 2`) rather than computing population standard deviation.

**Why:** Standard deviation measures overall spread -- how far all intervals deviate from the mean. Bucketization measures clustering -- how many intervals land near the same value. These are different questions:

- **Std dev (Beaconing):** "Is this channel's timing overall regular?" -- catches metronome-like precision
- **Clustering (C2 Channel):** "Does this channel have a repeated interval pattern?" -- catches repeated similar intervals even if other intervals are irregular

**Security Rationale:** Some C2 frameworks produce intervals that vary within a range (e.g., 58-62 seconds) but also include occasional long pauses. The Beaconing detector might reject this channel because the outliers inflate standard deviation. The C2 Channel detector would still find the 60-second cluster because enough deltas group there. The two detectors are complementary.

---

## Decision 2: Source Port Excluded from Grouping Key

**Decision:** Group by `{SourceIP}-{DestIP}:{DestPort}-{Protocol}` instead of including source port.

**Why:** Most C2 frameworks create a new TCP connection for each beacon, which means the OS assigns a new ephemeral source port each time. If source port were part of the grouping key, each beacon would land in its own single-event group and no pattern would ever emerge.

**Security Rationale:** This is a deliberate trade-off. Excluding source port makes the detector tolerant of ephemeral-port rotation -- a common C2 evasion technique. The cost is that two different processes on the same source machine talking to the same destination on the same port and protocol will be grouped together. In practice, this is rare for the same destination within a short time window, and the interval range gate further filters the results.

> **Note:** The Beaconing detector also excludes source port from its grouping key (it groups by `(SourceIP, DestinationIP, DestinationPort)`), but the C2 Channel detector additionally includes **Protocol** in the key, providing slightly finer-grained grouping.

---

## Decision 3: High Severity (Not Medium)

**Decision:** C2 channel findings emit at `Severity.High` directly, unlike Beaconing which starts at `Severity.Medium`.

**Why:** The clustering approach targets a more specific pattern than std dev-based detection. When enough deltas group together within a tolerance window within the C2 interval range, the signal is higher-fidelity. High severity reflects this confidence.

**Security Rationale:** The severity choice encodes a risk judgment. C2 channel detection means the detector found a repeated, interval-range-filtered periodic pattern -- not just low spread in the data. High severity ensures the finding surfaces at all profile levels (Medium profile shows High-and-above; High profile shows Info-and-above).

> **Profile visibility:** At Low profile, the detector is entirely disabled (`EnableC2Detection = false`), so no C2 channel findings appear regardless of severity. At Medium and High profiles, High-severity findings pass through the `MinSeverityToShow` filter.

---

## Decision 4: Protocol Included in Grouping Key

**Decision:** Group by `{SourceIP}-{DestIP}:{DestPort}-{Protocol}` instead of excluding protocol.

**Why:** A destination may accept connections on both TCP and UDP. These are fundamentally different communication patterns. Including protocol prevents mixing TCP beaconing with UDP DNS queries to the same destination.

**Security Angle:** Finer-grained grouping produces more precise attribution. The finding includes the protocol in the connection key, enabling targeted firewall rules and investigation.

---

## Decision 5: Pattern Reconstruction (Not Just Bucket Counting)

**Decision:** After identifying a valid bucket, reconstruct the actual events that participate in the pattern rather than just reporting the bucket statistics.

**Why:** An analyst needs to see the actual connections, not just "5 deltas landed in the 60-second bucket." Pattern reconstruction traces back from matching deltas to the original events, providing the timestamps, source IP, destination IP, and port for each participating connection.

**Security Rationale:** Evidence-based findings. When an analyst investigates a High-severity C2 channel finding, they can see exactly which connections formed the pattern. This supports incident timeline reconstruction and threat intel enrichment.

---

## Decision 6: Disabled on Low Profile

**Decision:** `EnableC2Detection = false` on the Low intensity profile.

**Why:** The Low profile prioritizes the highest-confidence signals with the fewest false positives. C2 channel detection with tolerance-based clustering has a broader detection surface than the Beaconing detector's std dev approach. On Low, the Beaconing detector (which is enabled) provides C2 coverage instead.

**Security Rationale:** Teams running at Low intensity want minimal noise. The C2 channel detector adds depth at Medium and High intensity where teams are willing to accept more findings in exchange for broader coverage. This respects the sensitivity gradient across profiles.

---

## Summary

| Decision | Security Principle | Operational Impact |
|----------|-------------------|-------------------|
| Tolerance clustering | Complementary detection lens | Catches patterns std dev may miss |
| Source port excluded | Ephemeral-port tolerance | Catches C2 that rotates source ports |
| High severity | Accurate risk communication | Immediate visibility on Medium/High profiles |
| Protocol in grouping key | Precise attribution | Prevents mixing TCP and UDP patterns |
| Pattern reconstruction | Evidence-based findings | Analysts see actual connections, not just statistics |
| Disabled on Low | Noise control | Low profile uses Beaconing for C2 coverage instead |

---

## Security Takeaways

1. **C2 channels are a post-compromise signal** -- detecting them means the host is already under adversary control, making it one of the highest-priority alerts
2. **Tolerance bucketization is the fingerprint** -- periodic communication that varies within a tolerance window is a strong indicator of automated C2
3. **Source port exclusion catches stealthier C2** -- many C2 frameworks use different ephemeral source ports per connection; excluding it from the grouping key prevents the pattern from being diluted
4. **High severity reflects urgency** -- unlike Beaconing (Medium), C2 channel findings start at High because the tolerance-based approach targets a more specific pattern
5. **Complementary to Beaconing** -- bucketization and std dev are different statistical lenses; together they provide broader C2 coverage
