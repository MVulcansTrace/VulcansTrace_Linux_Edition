# Detection Algorithm

---

## The Security Problem

After compromise, attackers need a persistent C2 channel. Most malware calls home at regular intervals, creating a timing signature that differs from human behavior. The detector must isolate each communication channel, measure timing regularity, and distinguish automated beaconing from noisier periodic traffic while acknowledging that some legitimate periodic software can still overlap statistically.

---

## Implementation Overview

A 9-step detection pipeline implemented in [BeaconingDetector.cs](../../../../../VulcansTrace.Linux.Engine/Detectors/BeaconingDetector.cs):

```text
Raw UnifiedEvents
    |
    v
Step A: Toggle Gate -------------- Why: Skip if beaconing detection is disabled
    |
    v
Step B: Keep external destinations and group by (SourceIP, DestinationIP, DestinationPort) -- Why: Isolate internet-facing channels independently
    |
    v
Step C: Order + Cap Samples --------- Why: Chronological order; cap downstream interval/statistics work
    |
    v
Step D: Min Events Gate -------------- Why: Skip channels with too few data points
    |
    v
Step E: Min Duration Gate ------------ Why: Require meaningful observation window
    |
    v
Step F: Interval Computation --------- Why: Transform timestamps into timing fingerprint
    |
    v
Step G: Outlier Trimming ------------- Why: Remove jitter extremes before statistics
    |
    v
Step H: Mean Interval Bounds --------- Why: Filter to C2 sweet spot, screen out very fast or very slow channels
    |
    v
Step I: StdDev Threshold Check ------- Why: Low std dev identifies automation
    |
    v
DetectionResult with Severity.Medium findings
    |
    v
Downstream: RiskEscalator may escalate to Critical;
MinSeverityToShow filter may suppress findings at Low intensity
```

---

## Step A: Feature Toggle

**Process:** If `profile.EnableBeaconing` is false or entries are empty, return immediately. A `CancellationToken` is checked at the start of each group iteration to support cooperative cancellation in long-running analyses.

**Rationale:** Zero-cost disable. Teams that don't need beaconing detection pay nothing.

**Security Angle:** Defense in depth -- the detector is one layer that can be toggled without affecting the rest of the pipeline.

---

## Step B: External Destination Filter and Tuple Grouping

**Process:** Entries whose destination IP is not publicly routable are ignored, then the remaining events are grouped by `(SourceIP, DestinationIP, DestinationPort)` -- isolating each external destination channel.

**Rationale:** Beaconing is modeled as periodic communication from an internal host to an external command-and-control destination. Internal periodic traffic, documentation ranges, link-local addresses, loopback, and other non-public destinations are excluded before statistical analysis. A single source IP may contact multiple external destinations with different timing patterns; grouping by source IP only would mix regular C2 traffic with irregular browsing and dilute the signal.

**Security Angle:** Precise attribution with fewer false positives. Each external channel gets its own verdict, enabling targeted firewall rules and threat intel enrichment per destination.

---

## Step C: Order and Cap Samples

**Process:** Chronologically sort each group. When `BeaconMaxSamplesPerTuple > 0`, if the group exceeds that limit, keep only the most recent entries (tail truncation). A value `<= 0` disables the cap entirely.

**Rationale:** Tail truncation prioritizes recent activity -- if beaconing is ongoing, the latest samples are most relevant. The cap bounds how much per-tuple history the detector carries into the statistical path.

**Security Angle:** Availability engineering. The cap bounds the interval-analysis and statistics work that happens after sorting, though the detector still sorts the full tuple first and the overall batch still scales with the full input set.

---

## Step D: Minimum Events Gate

**Process:** Skip groups with fewer events than `BeaconMinEvents`.

**Rationale:** Statistical analysis on 2-3 data points is unreliable. The minimum event count ensures the standard deviation is meaningful.

**Security Angle:** Prevents false positives from coincidence -- a few random connections to the same destination should not trigger beaconing alerts.

---

## Step E: Minimum Duration Gate

**Process:** Skip groups where the time span between first and last event is less than `BeaconMinDurationSeconds`.

**Rationale:** Five connections in 10 seconds could be a page load. The same five connections over 10 minutes is more suspicious. Duration adds temporal context.

**Security Angle:** Distinguishes burst activity from sustained periodic communication.

---

## Step F: Interval Computation

**Process:** Compute consecutive inter-arrival times: `(ordered[i].Timestamp - ordered[i-1].Timestamp).TotalSeconds`.

**Rationale:** Timestamps alone don't reveal regularity. Converting to intervals transforms raw data into a testable timing fingerprint.

**Security Angle:** This is where "malware is a metronome" becomes measurable. Regular intervals produce low standard deviation; irregular human behavior produces high standard deviation.

---

## Step G: Outlier Trimming

**Process:** Sort intervals, then symmetrically trim `BeaconTrimPercent` from each end. Example: with 10% trim on 10 intervals, remove 1 from the low end and 1 from the high end. Edge cases are handled gracefully -- if there are <=2 intervals, `trimPercent <= 0`, or the trim would consume all data, the original intervals are returned untrimmed.

**Rationale:** Network jitter, retransmissions, and occasional delays create outliers that inflate standard deviation. Symmetric trimming removes these without biasing the central tendency.

**Security Angle:** Makes the detector more tolerant of benign jitter and occasional anomalies. It helps with a few outliers, but sustained or deliberate jitter can still evade the detector.

---

## Step H: Mean Interval Bounds

**Process:** Skip the group if the mean interval falls outside `[BeaconMinIntervalSeconds, BeaconMaxIntervalSeconds]`.

**Rationale:** Without mean bounds, a heartbeat every 5 seconds (monitoring) or a cron job every hour (scheduled backup) could trigger a false positive. The bounds encode domain knowledge about C2 timing.

**Security Angle:** The mean bounds implement domain knowledge -- C2 malware commonly beacons in the 30s-900s range (Medium profile). They screen out very fast or very slow channels, but regular in-range health checks or other periodic software can still overlap and must be separated by the rest of the detector plus analyst context.

---

## Step I: StdDev Threshold Check

**Process:** Skip the group if the population standard deviation exceeds `BeaconStdDevThreshold`.

**Rationale:** The std dev threshold is the core automation detector: unsophisticated malware ticks like a clock (stdDev ~ 0), while human behavior flows irregularly (stdDev >> 0). Sophisticated C2 frameworks add deliberate jitter to evade this heuristic, which is why the std dev threshold is configurable per profile.

**Security Angle:** Low std dev on trimmed intervals is a strong indicator of automation. The threshold is profile-dependent so teams can trade sensitivity for false-positive rate.

---

## Complexity Analysis

| Metric | Value | Why |
|--------|-------|-----|
| **Time (worst-case)** | O(n log n) | Sorting events per tuple dominates |
| **Time (average)** | O(n log(n/t)) | t tuples, each sorted independently |
| **Space** | O(n) | Grouped entries and intervals in memory |

---

## Implementation Evidence

- [BeaconingDetector.cs](../../../../../VulcansTrace.Linux.Engine/Detectors/BeaconingDetector.cs): full pipeline from tuple grouping through finding emission
- [AnalysisProfile.cs](../../../../../VulcansTrace.Linux.Engine/AnalysisProfile.cs): eight beaconing-specific parameters (1 toggle + 7 thresholds)
- [BeaconingDetectorTests.cs](../../../../../VulcansTrace.Linux.Tests/Detectors/Baseline/BeaconingDetectorTests.cs): regular beaconing, irregular intervals, feature toggle, empty events, min events, multiple beacons, mean bounds, outlier trimming, sample cap, mixed traffic, tuple separation by port, finding property validation, and nftables format
- [ProfileComparisonTests.cs](../../../../../VulcansTrace.Linux.Tests/Integration/ProfileComparisonTests.cs): end-to-end analysis across all three intensity levels

---

## Security Takeaways

1. **Beaconing is a post-compromise signal** -- detecting it suggests the host may be under adversary control, making it one of the highest-priority alerts
2. **Statistical regularity is the fingerprint** -- automated tools produce timing patterns that standard deviation exposes reliably
3. **Correlation adds context** -- Beaconing + LateralMovement on the same host reflects real attack progression and warrants Critical severity
4. **Interval bounds filter noise** -- the C2 sweet spot (30s-900s on the default Medium profile) screens out many very fast or very slow channels, but regular in-range software can still overlap; on the Low profile, uncorrelated beaconing is filtered from results entirely
5. **Documented limitations matter** -- jitter-tolerant malware can evade the std dev threshold, and compensating controls exist for that gap
