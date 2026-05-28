# Detection Algorithm

---

## The Security Problem

After compromise, attackers need a persistent C2 channel. Many C2 frameworks beacon at intervals that vary slightly -- for example, 58 to 62 seconds instead of an exact 60 seconds. The Beaconing detector catches this with standard deviation, but the C2 Channel detector provides a complementary approach: tolerance-based interval clustering. It groups connections, clusters similar time deltas into tolerance buckets, and reconstructs the pattern events that participate in the periodic behavior.

---

## Implementation Overview

A 9-step detection pipeline implemented in [C2ChannelDetector.cs](../../../../../VulcansTrace.Linux.Engine/Detectors/C2ChannelDetector.cs):

```text
Raw UnifiedEvents
    |
    v
Step A: Toggle Gate -------------- Why: Skip if C2 detection is disabled
    |
    v
Step B: Tolerance Guard ----------- Why: Skip if tolerance is invalid (<= 0)
    |
    v
Step C: Group by Connection Key --- Why: Isolate each channel (source port excluded)
    |
    v
Step D: Sort + Compute Deltas ----- Why: Chronological order; transform timestamps into gaps
    |
    v
Step E: Cluster Deltas ------------ Why: Group similar intervals using greedy sliding window
    |
    v
Step F: Min Occurrences Gate ------ Why: Require enough deltas in a bucket to indicate a pattern
    |
    v
Step G: Interval Range Gate ------- Why: Filter to C2-appropriate intervals
    |
    v
Step H: Pattern Reconstruction ---- Why: Trace matching deltas back to original events
    |
    v
Step I: Min Pattern Events Gate --- Why: Require enough events to form a defensible finding
    |
    v
DetectionResult with Severity.High findings
    |
    v
Downstream: MinSeverityToShow filter controls visibility
```

---

## Step A: Feature Toggle

**Process:** If `profile.EnableC2Detection` is false or entries are empty, return immediately.

**Rationale:** Zero-cost disable. Teams that don't need C2 channel detection pay nothing. On the Low profile, the detector is disabled entirely.

**Security Angle:** Defense in depth -- the detector is one layer that can be toggled without affecting the rest of the pipeline, including the parallel Beaconing detector.

---

## Step B: Tolerance Guard

**Process:** If `profile.C2ToleranceSeconds <= 0`, return immediately. The tolerance value is central to the clustering algorithm; a non-positive tolerance would produce an invalid or zero-width grouping window.

**Rationale:** Defensive programming. The clustering algorithm uses `maxSpan = tolerance * 2` to define the window size; a non-positive tolerance would produce an invalid or zero-width window. The guard prevents nonsensical clustering.

**Security Angle:** Fail-safe behavior -- if the configuration is invalid, the detector produces no findings rather than garbage findings.

---

## Step C: Connection-Key Grouping

**Process:** Entries are grouped by `{SourceIP}-{DestinationIP}:{DestinationPort}-{Protocol}`, with groups having fewer than `C2MinGroupSize` events filtered out (default 3 on Medium/High, 4 on Low).

**Rationale:** A single source IP may contact multiple destinations with different timing patterns. Grouping by the full connection key (excluding source port) isolates each channel independently. The 3-event minimum ensures there are at least 2 deltas to analyze.

**Security Angle:** The source port is **deliberately excluded** from the grouping key. Many C2 frameworks use a different ephemeral source port for each connection -- for example, `:51001`, `:51002`, `:51003`. If source port were included, each connection would land in its own group and the periodic pattern would never emerge. This is a key difference from the Beaconing detector, which groups by `(SourceIP, DestinationIP, DestinationPort)` without protocol.

---

## Step D: Sort and Compute Deltas

**Process:** Chronologically sort each group, then compute consecutive inter-arrival times: `(ordered[i].Timestamp - ordered[i-1].Timestamp).TotalSeconds`.

**Rationale:** Timestamps alone don't reveal periodicity. Converting to deltas transforms raw data into a testable timing fingerprint. Sorting is necessary because events may arrive out of order.

**Security Angle:** This is where "C2 calls home every 60 seconds" becomes measurable. Consistent deltas cluster into the same tolerance group; irregular deltas scatter across separate groups.

---

## Step E: Cluster Deltas

**Process:** Deltas are sorted by value, then grouped using a greedy sliding window. Starting from each position, the algorithm collects consecutive deltas while `delta - startDelta <= tolerance * 2`. If the window contains enough deltas (`>= C2MinOccurrences`), it becomes a group with the average delta as the interval. The start pointer then jumps past the window; otherwise it increments by one.

**Example:** With tolerance = 5.0s (`maxSpan = 10.0s`):
- Sorted deltas: [58, 60, 62, 65, 120]
- Window from 58: includes 58, 60, 62, 65 (all within 58+10=68). Count = 4. Group interval = avg([58,60,62,65]) = 61.25s.
- Window from 120: only 120. Count = 1 < minOccurrences. Skip.

**Rationale:** This greedy clustering groups intervals that are "close enough" to each other without requiring exact matching. Sorting first ensures the algorithm runs in O(n log n) and the sliding window efficiently finds natural clusters. The average interval represents the group's central tendency better than a rounded bucket key when deltas are spread across a range.

**Security Angle:** This approach catches C2 that varies within the tolerance window. On Medium profile with 5s tolerance, a C2 framework that beacons every 58-65 seconds is caught as a single cluster. On High profile with 8s tolerance (`maxSpan = 16s`), an even wider spread of deltas can be grouped together, but the profile also requires fewer occurrences (2 vs 3) and fewer pattern events (4 vs 6).

---

## Step F: Minimum Occurrences Gate

**Process:** Filter buckets where the count of deltas is less than `C2MinOccurrences`.

**Rationale:** A single delta matching a bucket is coincidence. Two or three matching deltas suggest a pattern. The threshold scales with sensitivity: 5 on Low (unused), 3 on Medium, 2 on High.

**Security Angle:** Prevents false positives from random interval clustering. The minimum occurrence threshold ensures the pattern is repeated enough to be statistically meaningful.

---

## Step G: Interval Range Gate

**Process:** Skip the bucket if its interval key falls outside `[C2MinIntervalSeconds, C2MaxIntervalSeconds]`.

**Rationale:** C2 malware needs responsive communication -- fast enough for command delivery, slow enough to avoid drawing attention. The bounds encode this domain knowledge.

| Profile | Min Interval | Max Interval | Rationale |
|---------|-------------|-------------|-----------|
| Low (unused) | 120s | 3600s | Conservative -- very long patterns only |
| Medium | 60s | 1800s | Standard C2 sweet spot |
| High | 30s | 1800s | Catches faster beacons with tighter bounds |

**Security Angle:** Without interval bounds, a heartbeat every 5 seconds (monitoring) or a cron job every hour (scheduled backup) could trigger a false positive. The bounds encode domain knowledge about C2 timing.

---

## Step H: Pattern Reconstruction

**Process:** For each surviving bucket, the detector already knows which delta indices belong to the bucket from the grouping step in Step E. It reconstructs the participating events directly from those indices: for each delta index `i` in the bucket, both `orderedEvents[i]` and `orderedEvents[i + 1]` are added to the pattern set. This avoids re-scanning all event pairs for every bucket.

**Rationale:** The clustering step identified which deltas group together. Pattern reconstruction traces back to the actual events that produced those deltas, providing concrete evidence for the finding. Using precomputed indices eliminates repeated O(n) scans when multiple buckets survive the prior gates.

**Security Angle:** The finding includes the actual events, not just the statistical summary. An analyst can see exactly which connections formed the pattern, enabling verification and investigation.

---

## Step I: Minimum Pattern Events Gate

**Process:** Skip the bucket if the reconstructed pattern has fewer events than `C2MinPatternEvents`. Otherwise, emit a Finding.

**Rationale:** The pattern events threshold is higher than the occurrences threshold because it counts actual events (not deltas). A pattern with 3 deltas involves 4 events. The threshold ensures the finding represents a sustained pattern, not a brief coincidence.

**Security Angle:** High-severity findings have a high bar. The minimum pattern events threshold prevents low-confidence findings from generating High-severity alerts.

---

## Complexity Analysis

| Metric | Value | Why |
|--------|-------|-----|
| **Time (worst-case)** | O(n log n) | Sorting events per group dominates |
| **Time (average)** | O(n log(n/t)) | t groups, each sorted independently |
| **Space** | O(n) | Grouped entries, deltas, and pattern events in memory |

---

## Implementation Evidence

- [C2ChannelDetector.cs](../../../../../VulcansTrace.Linux.Engine/Detectors/C2ChannelDetector.cs): full pipeline from connection-key grouping through finding emission
- [AnalysisProfile.cs](../../../../../VulcansTrace.Linux.Engine/AnalysisProfile.cs): seven C2-specific parameters (1 toggle + 6 thresholds)
- [C2ChannelDetectorTests.cs](../../../../../VulcansTrace.Linux.Tests/Detectors/C2ChannelDetectorTests.cs): periodic pattern detection, disabled toggle, and no-pattern rejection
- [AnalysisProfileProvider.cs](../../../../../VulcansTrace.Linux.Engine/Configuration/AnalysisProfileProvider.cs): built-in Low (disabled), Medium, and High presets

---

## Security Takeaways

1. **C2 channels are a post-compromise signal** -- detecting them means the host is already under adversary control, making it one of the highest-priority alerts
2. **Tolerance bucketization is the fingerprint** -- periodic communication that varies within a tolerance window is a strong indicator of automated C2
3. **Source port exclusion catches stealthier C2** -- many C2 frameworks use different ephemeral source ports per connection; excluding it from the grouping key prevents the pattern from being diluted
4. **High severity reflects urgency** -- unlike Beaconing (Medium), C2 channel findings start at High because the tolerance-based approach targets a more specific pattern
5. **Complementary to Beaconing** -- bucketization and std dev are different statistical lenses; together they provide broader C2 coverage
