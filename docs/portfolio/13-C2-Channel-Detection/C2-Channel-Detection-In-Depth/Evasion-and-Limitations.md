# Evasion and Limitations

> Detector limitations and acceptable trade-offs for the current threat model.

---

## Known Limitations

| Limitation | What It Means In Practice | Enhancement Path |
|-----------|--------------------------|-----------------|
| Jitter beyond tolerance | C2 that varies more than the tolerance window spreads across multiple buckets | Higher tolerance profiles, or use Beaconing detector with std dev |
| Domain flux | Rotating C2 destinations splits events across groups | Cross-tuple correlation by source IP + timing |
| DNS tunneling | C2 over DNS may not appear in firewall connection logs | DNS-specific analysis layer |
| No payload inspection | Cannot distinguish C2 from legitimate HTTPS traffic | Deep packet inspection integration |
| Single-host scope | Cannot detect distributed C2 across multiple compromised hosts | Subnet-level correlation |
| Encrypted channels | TLS-encrypted C2 traffic is indistinguishable from legitimate HTTPS by timing alone | Certificate analysis, JA3/JA3S fingerprinting |
| Irregular intervals | C2 frameworks that use heavily randomized intervals may not cluster | Beaconing detector as complementary approach; entropy analysis |
| Bucket boundary effects | Intervals near tolerance boundaries may land in adjacent buckets | Overlapping buckets or continuous similarity measures |

---

## The Evasion Arms Race

The detector operates in a statistical arms race against malware authors. The tolerance parameter defines how much interval variation the detector accepts:

| Malware Version | Behavior | Tolerance Buckets | Medium (5s) | High (8s) |
|----------------|----------|-------------------|-------------|-----------|
| v1: Perfect | Fixed 60s intervals | All land in 60s bucket | **Caught** | **Caught** |
| v2: Light jitter | 57-63s intervals | Clustered within 10s span (tolerance 5s) | **Caught** | Clustered within 16s span (tolerance 8s) -- may still reach min occurrences |
| v3: Heavy jitter | 40-80s intervals | Spread across many groups | Usually missed | Usually missed |
| v4: Multi-interval | Alternates 30s and 90s | Two separate buckets | Each bucket has half the deltas -- may not reach min occurrences | Same problem |

> **Note on profile interaction:** The Medium profile's tolerance (5s) and High profile's tolerance (8s) both use a greedy sliding window with `maxSpan = tolerance * 2`. High's larger tolerance can group more deltas together, and its minimum interval is lower (30s vs 60s), allowing it to catch faster beacons. The key difference is that High requires fewer occurrences (2 vs 3) and fewer pattern events (4 vs 6).

**The trade-off:** Wider tolerance catches more jitter-tolerant C2 but also clusters more legitimate traffic into the same groups. Tighter tolerance is more specific but requires more precise beaconing. The profile gradient lets teams choose their position on this spectrum.

### What Users Actually See

1. **Detector disabled on Low profile:** `EnableC2Detection = false` on Low, so no C2 channel findings appear regardless of what the algorithm would produce.

2. **Severity filtering:** Medium profile shows High-and-above, High profile shows Info-and-above. Since C2 channel findings emit at `Severity.High`, they are visible on both Medium and High profiles.

3. **Complementary to Beaconing:** The Beaconing detector provides parallel C2 coverage. A pattern that evades the C2 Channel detector's bucketization may still be caught by the Beaconing detector's std dev analysis, and vice versa.

---

## Why These Trade-Offs Are Acceptable Here

The detector targets a specific threat model: **C2 communication with intervals that cluster within a tolerance window**. This covers:

- Commodity malware with fixed or lightly jittered intervals
- C2 frameworks that use a base interval with small random variation
- Beaconing patterns where the Beaconing detector's std dev threshold is too strict

The accepted trade-offs:

- **Heavily randomized traffic is not caught** -- that requires fundamentally different techniques (entropy analysis, behavioral baselines, ML)
- **Payloads are not inspected** -- that requires a different data source (DPI proxy, TLS decryption)
- **Single-host scope** -- distributed C2 requires correlation across hosts
- **Greedy clustering is used** -- other methods (autocorrelation, spectral analysis) would catch different patterns but add complexity

---

## Improvement Roadmap

```
Phase 1: Overlapping Buckets (catch intervals near bucket boundaries)
Phase 2: Multi-Bucket Correlation (catch C2 with multiple distinct intervals)
Phase 3: Cross-Tuple Correlation by Source IP (catch domain flux)
Phase 4: Streaming Architecture (cloud-scale with rolling windows)
Phase 5: Adaptive Tolerance (auto-tune tolerance based on observed jitter distribution)
```

**Phase 1 -- Overlapping Buckets:** Instead of a single bucket per interval, use overlapping windows so intervals near the tolerance boundary contribute to both adjacent buckets. This prevents edge effects from splitting a coherent pattern across two buckets.

**Phase 3 -- Cross-Tuple Correlation:** Group by source IP only, then look for similar timing patterns across different destinations. A C2 framework using domain flux would produce different destination IPs but similar beacon timing from the same source.

---

## Implementation Evidence

- [C2ChannelDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/C2ChannelDetector.cs): the clustering thresholds and pattern reconstruction logic that define the detection boundary
- [AnalysisProfile.cs](../../../../VulcansTrace.Linux.Engine/AnalysisProfile.cs): six C2-specific threshold parameters (plus C2MinGroupSize) that can be tuned to shift the sensitivity trade-off
- [C2ChannelDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/C2ChannelDetectorTests.cs): includes periodic pattern, disabled toggle, and no-pattern scenarios that show where the current detection boundary sits
- [AnalysisProfileProvider.cs](../../../../VulcansTrace.Linux.Engine/Configuration/AnalysisProfileProvider.cs): Low, Medium, and High presets with different tolerance and threshold values

---

## Security Takeaways

1. **C2 channels are a post-compromise signal** -- detecting them means the host is already under adversary control, making it one of the highest-priority alerts
2. **Tolerance bucketization is the fingerprint** -- periodic communication that varies within a tolerance window is a strong indicator of automated C2
3. **Source port exclusion catches stealthier C2** -- many C2 frameworks use different ephemeral source ports per connection; excluding it from the grouping key prevents the pattern from being diluted
4. **High severity reflects urgency** -- unlike Beaconing (Medium), C2 channel findings start at High because the tolerance-based approach targets a more specific pattern
5. **Complementary to Beaconing** -- bucketization and std dev are different statistical lenses; together they provide broader C2 coverage
