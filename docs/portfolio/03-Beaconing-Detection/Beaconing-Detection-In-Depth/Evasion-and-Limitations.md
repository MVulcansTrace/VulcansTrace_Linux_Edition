# Evasion and Limitations

> Detector limitations and acceptable trade-offs for the current threat model.

---

## Known Limitations

| Limitation | What It Means In Practice | Enhancement Path |
|-----------|--------------------------|-----------------|
| Jitter-tolerant malware | Deliberate timing randomness can evade stricter profiles | Higher sensitivity profiles, coefficient of variation |
| Domain flux | Rotating C2 destinations splits across tuples | Cross-tuple correlation by source IP + timing |
| DNS tunneling | C2 over DNS, not visible in firewall connection logs | DNS-specific analysis layer |
| No payload inspection | Cannot distinguish C2 from legitimate HTTPS | Deep packet inspection integration |
| Single-host scope | Cannot detect distributed C2 across multiple compromised hosts | Subnet-level correlation |
| Encrypted channels | TLS-encrypted C2 traffic is indistinguishable from legitimate HTTPS by timing alone | Certificate analysis, JA3/JA3S fingerprinting |

---

## The Evasion Arms Race

The detector operates in a statistical arms race against malware authors. The examples below are illustrative threshold-level reasoning, not guarantees for every possible sample set:

| Malware Version | Behavior | Theoretical StdDev | Low (3.0) | Medium (5.0) | High (8.0) |
|----------------|----------|-------------------|-----------|--------------|-------------|
| v1: Perfect | Fixed 60s intervals | 0.0 | **Caught** | **Caught** | **Caught** |
| v2: Light jitter | Small random delay around a regular mean | Depends on sample set and trimming | Often missed | Sometimes caught | More likely caught |
| v3: Heavy jitter | Large random delay around a regular mean | Depends on sample set and trimming | Usually missed | Usually missed | Sometimes still missed |

> **Note on Low profile visibility:** `BeaconingDetector` always emits Medium-severity findings. At Low profile, `MinSeverityToShow = Severity.High`, so standalone beaconing findings are discarded. The only way a Low-profile beaconing finding surfaces is if correlation with LateralMovement causes `RiskEscalator` to escalate it to Critical.
>
> **Note on jitter outcomes:** Light jitter outcomes depend on the actual interval set. The detector sorts intervals and trims outliers before computing StdDev, so the same nominal jitter pattern can land on different sides of the threshold depending on how many samples exist and where the outliers fall.

**The trade-off:** As sensitivity increases (higher std dev threshold), the detector catches jitter-tolerant malware but also flags more legitimate periodic traffic. This is the fundamental sensitivity-specificity tension in any statistical detector.

### What Users Actually See

The table above describes detection-logic outcomes (StdDev vs threshold). The full pipeline adds two transformations that change what users actually see:

1. **Severity filtering:** Each profile sets `MinSeverityToShow` -- Low filters to High-and-above, Medium to Medium-and-above, High to Info-and-above. Since `BeaconingDetector` always emits Medium severity, standalone beaconing findings are invisible at Low profile regardless of the StdDev threshold.

2. **Risk escalation** (`RiskEscalator`): When a single host triggers time-correlated Beaconing and LateralMovement findings, `RiskEscalator` escalates those participating findings to Critical severity. This means correlated threats surface even at Low profile, where standalone beaconing would be suppressed.

---

## Why These Trade-Offs Are Acceptable Here

The detector targets a specific threat model: **automated C2 beaconing with moderate timing regularity**. This covers the majority of commodity malware and many APT tools that use fixed or lightly randomized intervals.

The accepted trade-offs:

- **Perfectly randomized traffic is not caught** -- that requires fundamentally different techniques (entropy analysis, behavioral baselines, ML)
- **Payloads are not inspected** -- that requires a different data source (DPI proxy, TLS decryption)
- **Single-host scope** -- distributed C2 requires correlation across hosts
- **Population std dev is used** -- other metrics (coefficient of variation, autocorrelation) would catch different patterns but add complexity

---

## Improvement Roadmap

```
Phase 1: Coefficient of Variation (catch proportional jitter)
Phase 2: Autocorrelation Analysis (catch periodic patterns within jitter)
Phase 3: Cross-Tuple Correlation (catch domain flux by source IP)
Phase 4: Streaming Architecture (cloud-scale with rolling windows)
Phase 5: ML Behavioral Baselines (adaptive detection)
```

**Phase 1 -- Coefficient of Variation:** The most impactful enhancement. Instead of a fixed std dev threshold, normalize by the mean: `CV = stdDev / mean`. A channel with 60s +- 20s intervals has CV ~ 0.33. A channel with 600s +- 20s intervals has CV ~ 0.03. This catches proportional jitter regardless of beacon frequency.

**Phase 4 -- Streaming Architecture:** The current batch approach processes all entries at once. For cloud-scale SIEM (billions of events/day), the algorithm would shift to rolling windows with Welford's online algorithm for O(1) variance computation. The core statistical logic stays the same; the implementation changes from batch to stateful streaming.

---

## Implementation Evidence

- [BeaconingDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/BeaconingDetector.cs): the current statistical thresholds that define the detection boundary
- [AnalysisProfile.cs](../../../../VulcansTrace.Linux.Engine/AnalysisProfile.cs): seven beaconing-specific threshold parameters that can be tuned to shift the sensitivity trade-off
- [BeaconingDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/Baseline/BeaconingDetectorTests.cs): includes regular beaconing, outlier trimming, sample-cap, and noisy-periodic scenarios that show where the current statistical boundary sits
- [RiskEscalator.cs](../../../../VulcansTrace.Linux.Engine/RiskEscalator.cs): escalates correlated Beaconing + LateralMovement findings to Critical severity

---

## Security Takeaways

1. **Beaconing is a post-compromise signal** -- detecting it suggests the host may be under adversary control, making it one of the highest-priority alerts
2. **Statistical regularity is the fingerprint** -- automated tools produce timing patterns that standard deviation exposes reliably
3. **Correlation adds context** -- Beaconing + LateralMovement on the same host reflects real attack progression and warrants Critical severity
4. **Interval bounds filter noise** -- the C2 sweet spot (30s-900s on the Medium profile, the CLI default and general-use recommendation) screens out many very fast or very slow channels, but regular in-range software can still overlap; on the Low profile, uncorrelated beaconing is filtered from results entirely
5. **Documented limitations matter** -- jitter-tolerant malware can evade the std dev threshold, and compensating controls exist for that gap
