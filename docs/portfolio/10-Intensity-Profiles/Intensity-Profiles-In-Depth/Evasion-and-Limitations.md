# Intensity Profiles — Evasion and Limitations

## Known Limitations

| Limitation | Severity | Impact |
|---|---|---|
| Fixed three-tier model | Medium | Cannot fine-tune individual thresholds without override |
| No runtime profile switching | Medium | Profile is resolved once per analysis call |
| Shared policy lists are not validated | Low | AdminPorts could theoretically be empty |
| No profile versioning | Low | No way to distinguish between profile tuning iterations |
| Threshold gaps between tiers | Low | Attacks between Low and Medium thresholds may be inconsistently detected |
| No adaptive threshold adjustment | Medium | Profiles cannot adjust based on network baseline |

---

## Fixed Three-Tier Model

The system provides exactly three presets: Low, Medium, and High. Operators who need intermediate sensitivity (e.g., between Medium and High port scan thresholds of 15 and 8) must use the override parameter to construct a custom profile programmatically. There is no UI or configuration file mechanism for creating custom presets.

**Mitigation:** The `overrideProfile` parameter in `SentryAnalyzer.Analyze` accepts any `AnalysisProfile` instance. Operators can create custom profiles using `with` expressions:

```csharp
var custom = provider.GetProfile(IntensityLevel.Medium) with { PortScanMinPorts = 10 };
analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None, custom);
```

---

## No Runtime Profile Switching

The profile is resolved once near the start of `SentryAnalyzer.Analyze` (line 114) and remains immutable for the entire analysis run. If an analyst wants to compare results across profiles, they must run separate analysis calls — which re-normalize the log data each time.

**Mitigation:** The `ProfileComparisonTests` integration test demonstrates the pattern: run `Analyze` three times with different intensity levels and compare results. A future optimization could cache normalized events and only re-run detection.

---

## Threshold Gap Between Tiers

The discrete thresholds create gaps where an attack is detectable at one tier but not the next-lower tier. For example:

- A 12-port scan: detected at High (threshold 8) but not at Medium (threshold 15) or Low (threshold 30)
- A 25-port scan: detected at Medium (threshold 15) and High (threshold 8) but not at Low (threshold 30)
- A 35-port scan: detected at all tiers

This means the choice of profile directly affects which attacks are visible.

**Mitigation:** This is intentional by design — the tiers represent expert-tuned sensitivity levels, not a continuous spectrum. Operators who need finer granularity should use the override parameter.

---

## No Adaptive Threshold Adjustment

Profiles use static thresholds that do not adapt to the network's baseline behavior. A network that routinely generates 500 events per minute would benefit from higher flood thresholds than a network that generates 50 events per minute, but the profiles cannot make this distinction.

**Mitigation:** Adaptive thresholding would require a network baseline calculation phase — potentially as a pre-analysis step that generates a custom profile. This is a natural extension point for the override mechanism.

---

## No Profile Versioning

The profile configuration is embedded in source code. There is no version identifier, changelog, or mechanism to distinguish between profile tuning iterations. If thresholds change between software releases, operators have no way to know that the "Medium" profile in v2.0 is different from the "Medium" profile in v1.0.

**Mitigation:** Add a `ProfileVersion` or `ProfileHash` property to `AnalysisProfile` for tracking. Document threshold changes in release notes.

---

## Improvement Roadmap

| Priority | Improvement | Effort |
|---|---|---|
| High | Custom profile API (builder pattern or config file) | Medium |
| High | Normalized event caching for cross-profile comparison | Medium |
| Medium | Adaptive threshold baseline calculation | High |
| Medium | Profile versioning and change tracking | Low |
| Low | Intermediate presets (e.g., Medium-Low, Medium-High) | Low |
| Low | Network baseline pre-analysis phase | High |
| Low | Profile recommendation engine based on log characteristics | High |

---

## Security Takeaways

- The fixed three-tier model is a deliberate trade-off: simplicity and testability over infinite configurability
- The override parameter provides a safety valve for specialized analysis without compromising the tested presets
- Threshold gaps between tiers are intentional — each tier catches what the previous tier misses, which is the point of progressive sensitivity
- The lack of adaptive thresholds is the most impactful limitation for diverse network environments
- Profile versioning should be addressed before the next release to maintain reproducibility guarantees
