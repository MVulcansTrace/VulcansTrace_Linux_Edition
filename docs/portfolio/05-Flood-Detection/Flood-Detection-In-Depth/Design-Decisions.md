# Flood Detection — Design Decisions

> The flood detector's design prioritizes simplicity and speed — for a volume-based detector, the algorithm must itself be immune to the flooding it detects.

---

## Decision 1: Simple Event Count Over Distinct-Target Counting

**Decision:** Count total events in the window rather than distinct destination IPs or ports.

**Rationale:** A flood is defined by volume, not variety. Whether an attacker hits one port or a thousand, the impact on the target is determined by the number of connection attempts. The per-source setup sorts once via `OrderBy`; the hot counting loop uses only integer arithmetic — O(1) amortized per window position, with no LINQ, no allocation, and no `Distinct()` call in the inner loop.

**Security Rationale:** DoS attacks targeting a single service (e.g., SYN flood on port 80) produce high volume to one destination. Distinct-target counting would miss these concentrated attacks.

**Business Value:** Simpler code, faster execution, and more accurate detection of concentrated floods.

---

## Decision 2: No IP Classification Filter

**Decision:** Do not filter to internal or external sources — analyze all source IPs.

**Rationale:** Floods can originate from external attackers (DDoS), compromised internal hosts (botnet), or misconfigured internal services. Restricting to one category would miss the others. The lateral movement detector needs internal-to-internal filtering because its threat model is specific; the flood detector's threat model is universal.

**Security Rationale:** Insider threats, compromised IoT devices, and misconfigured applications can all generate internal floods. Excluding any source category creates a blind spot.

**Business Value:** One detector covers all flood scenarios without requiring operators to run separate analyses for internal and external sources.

---

## Decision 3: Fixed Window Duration Across Profiles

**Decision:** Keep `FloodWindowSeconds` at 60 for all profiles; only vary `FloodMinEvents`.

**Rationale:** The 60-second window aligns with common DoS detection practice and provides a consistent time unit for operators to reason about. Varying only the event threshold keeps the mental model simple: "how many events in one minute is too many?"

**Security Rationale:** Changing the window duration changes what constitutes a "burst." A 60-second window is long enough to capture real attacks but short enough to exclude slow background noise.

**Business Value:** Operators need to understand only one variable (event threshold) when tuning sensitivity, reducing misconfiguration risk.

---

## Decision 4: Burst-Aware Finding Emission

**Decision:** Emit one finding per contiguous above-threshold burst rather than one per event or one per source.

**Rationale:** A source may flood in multiple distinct time-separated bursts. The detector uses an `inFinding` state flag to track whether it is currently inside an active above-threshold window. When the threshold is first crossed, a finding is created. As long as the event count stays above threshold, the same finding is extended and the `peakCount` counter is updated. When the count drops below threshold, the finding is finalized with its actual time range and peak event count. After the loop ends, any active finding is closed with the final event's timestamp.

**Security Rationale:** A detector that floods the alert system while detecting a flood would be counterproductive. The `inFinding` pattern prevents duplicate findings from overlapping windows while still capturing separate attack episodes — one clear alert per burst.

**Business Value:** Clean, actionable alert stream that doesn't require manual deduplication, with a complete timeline of attacker activity.

---

## Decision 5: Integer-Only Window Count

**Decision:** Use `int windowCount = end - start + 1` instead of LINQ-based counting.

**Rationale:** The two-pointer invariant guarantees that events from `start` to `end` (inclusive) are within the window. Counting them is simple pointer arithmetic — no enumeration, no allocation, no overhead.

**Security Rationale:** Minimal computational overhead means the detector can handle log files with millions of events without becoming a bottleneck in the analysis pipeline.

**Business Value:** Faster analysis on large log files, lower infrastructure requirements.

---

## Summary

| Decision | Trade-off | Security Outcome |
|---|---|---|
| Event count over distinct targets | Misses variety patterns | Accurate concentrated-flood detection |
| No IP classification filter | More events to process | Covers internal and external floods |
| Fixed 60s window | Less temporal flexibility | Simple, consistent operator model |
| Burst-aware emission | One finding per contiguous burst | Prevents duplicate findings while capturing repeated episodes |
| Integer-only window count | Less readable than LINQ | Maximum performance on large logs |
