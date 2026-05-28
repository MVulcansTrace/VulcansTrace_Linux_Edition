# Flood Detection — Evasion and Limitations

## Known Limitations

| Limitation | Severity | Impact |
|---|---|---|
| Single-source assumption | High | Distributed floods (DDoS) with many low-rate sources evade detection |
| No protocol awareness | Low | Cannot distinguish SYN floods from legitimate high-volume services |
| Sliding window (no memory) | Medium | Pulsed attacks with pauses longer than the window period evade detection as separate episodes |
| No destination context | Low | Cannot differentiate targeted DoS from broad scanning |
| No baseline learning | Medium | Legitimate high-volume sources (backup servers, CDNs) may generate false positives |
| None (multi-episode supported) | — | The detector already produces separate findings for distinct time-separated bursts from the same source |

---

## Distributed Floods (DDoS)

The detector groups events by source IP, so a distributed attack using thousands of IPs each generating sub-threshold traffic will not trigger detection. If 1,000 sources each generate 99 events in 60 seconds, the total impact is 99,000 events/minute but no single source crosses the threshold.

**Mitigation:** Aggregate flood detection across IP ranges or ASN prefixes. Future versions could implement a "global event rate" detector that monitors total system throughput independent of source.

---

## Slow-Rate and Low-and-Slow Attacks

Attackers who maintain a rate just below the threshold (e.g., 99 events per 60 seconds) will never trigger the detector, yet can still degrade service over extended periods.

**Mitigation:** Implement a cumulative scoring system that tracks sustained elevated rates. A secondary "slow burn" detector with longer windows and lower thresholds could complement the primary flood detector.

---

## Legitimate High-Volume Traffic

Backup servers, monitoring systems, and software update services can generate bursts of legitimate connections that exceed flood thresholds, especially in the Low profile (400 events / 60s).

**Mitigation:** Implement source whitelisting in the analysis profile, or add destination-aware baselines that learn which source-destination pairs represent known high-volume services.

---

## Pulsed Attacks

An attacker who generates 200 events in 30 seconds, pauses for at least 60 seconds (the full window width), then repeats the burst can create genuinely separate episodes. Because the sliding window has no memory of past episodes, each burst is evaluated independently — and in the Low profile (threshold 400), each 200-event burst falls below the threshold. In the Medium profile (threshold 200) each burst meets the threshold exactly, and in the High profile (threshold 100) each burst well exceeds it.

**Mitigation:** The two-pointer sliding window is already more resistant to this than fixed bins, but adding a "peak detection" mode that remembers recent window maxima would improve coverage.

---

## Repeated Flood Episodes

The detector uses burst-aware tracking (`inFinding` state) that produces one finding per contiguous above-threshold window. Separate time-separated bursts from the same source already generate separate findings, verified by `Detect_TwoDistinctFloodBurstsSameSource_ReturnsAtLeastTwoFindings`.

---

## Application-Layer Floods

The detector operates on normalized firewall log events from iptables and nftables. Application-layer attacks (e.g., HTTP floods with valid TCP handshakes, slow POST attacks) produce normal connection volumes and will not be detected.

**Mitigation:** Layer with application-layer monitoring (web server access logs, application performance metrics) for comprehensive flood coverage.

---

## Improvement Roadmap

| Priority | Improvement | Effort |
|---|---|---|
| High | Source whitelist in analysis profile | Low |
| High | Aggregate rate monitoring across IP ranges | Medium |
| High | Adaptive window duration based on event volume | Low |
| Medium | Baseline learning for known high-volume sources | Medium |
| Medium | Cumulative scoring for slow-rate attacks | Medium |
| Low | Peak detection mode for pulsed attacks | Low |
| Low | Application-layer flood correlation | High |

---

## Security Takeaways

- The detector is optimized for single-source volumetric attacks and does not cover distributed or application-layer floods
- DDoS is the most significant evasion vector — layering with upstream DDoS mitigation services is recommended
- Burst-aware tracking emits one finding per contiguous above-threshold burst; time-separated episodes from the same source produce separate findings
- False positives from legitimate high-volume sources can be mitigated through profile configuration
- Future versions should consider aggregate rate monitoring to address the distributed attack gap
