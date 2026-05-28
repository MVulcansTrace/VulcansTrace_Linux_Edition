# Novelty Detection — Technical Snapshot

> The novelty detector finds the needles that volume-based detectors miss — external destinations that appear no more than `NoveltyMaxGlobalOccurrences` times (default 1, i.e. strict singletons). In compact production C#, it uses a two-pass algorithm (frequency counting, then rarity extraction) followed by grouping novel destinations by source IP to produce aggregated findings with comma-separated target lists. Each source IP's novel destinations are collected into one finding with up to 5 destination `IP:Port` entries and a count-based summary. Disabled by default in low-sensitivity profiles, it activates for medium and high-intensity analysis where deep forensic coverage is required.
>
> This subsystem demonstrates skills in **frequency-based anomaly detection**, **two-pass algorithm design**, **source-grouped reporting**, and **conservative severity assignment**.

---

## Implementation Overview

The detector receives a pre-normalized `UnifiedEvent` list, filters to events with external destinations, builds a frequency dictionary keyed by (DestIP, DestPort), then iterates again to flag events where the destination was seen no more than `NoveltyMaxGlobalOccurrences` times (default 1, i.e. strict singletons). Novel destinations are grouped by source IP — each source produces one finding with a comma-separated target list (up to 5 entries + `"..."`), the min/max time range across its destinations, and a count-based description.

---

## Key Metrics

| Metric | Value |
|---|---|
| Test coverage | Unit-tested across singleton detection and profile gating |
| Time complexity | O(n) — two passes, hash-based counting |
| Space complexity | O(n) — frequency dictionary |
| Numeric thresholds | `NoveltyMaxGlobalOccurrences` — configurable rarity threshold (default 1) |
| Profile availability | Medium and High only |
| MITRE ATT&CK coverage | T1046, T1018, TA0007 |

---

## Why It Matters

- **Reconnaissance detection** — attackers often probe a target once to test connectivity before committing to a full attack
- **Exfiltration testing** — sophisticated attackers test exfiltration channels with a single small transfer before sending bulk data
- **New infrastructure detection** — connections to newly stood-up C2 servers or drop sites appear as singletons before they become regular beacons
- **Deep forensic value** — singletons provide leads for investigation that volume-based detectors systematically ignore

---

## Key Evidence

- [NoveltyDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/NoveltyDetector.cs) — two-pass singleton detection
- [NoveltyDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/Baseline/NoveltyDetectorTests.cs) — test suite

---

## Key Design Choices

1. **Two-pass over single-pass** — frequency dictionary must be complete before singletons can be identified; a single-pass approach would miss later duplicates
2. **(DestIP, DestPort) composite key** — same IP on different ports represents different services and different risk profiles
3. **Source-grouped findings** — singletons are grouped by source IP with comma-separated target lists (up to 5 + "...") for concise reporting
4. **Low severity** — a singleton is suggestive but not conclusive; avoids alert fatigue on what could be benign one-time connections
5. **Disabled in Low profile** — singletons generate significant noise; only appropriate for higher-sensitivity analysis
6. **Configurable rarity threshold** — `NoveltyMaxGlobalOccurrences` (default 1) controls the maximum occurrence count that still qualifies as novel; set to 3 to catch near-singletons
