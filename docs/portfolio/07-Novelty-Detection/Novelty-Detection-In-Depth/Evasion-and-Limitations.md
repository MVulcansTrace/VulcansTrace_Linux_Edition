# Novelty Detection — Evasion and Limitations

## Known Limitations

| Limitation | Severity | Impact |
|---|---|---|
| Double-tap evasion | High (default) / Medium (if threshold > 1) | Connecting to the same target more than `NoveltyMaxGlobalOccurrences` times defeats detection |
| High noise on busy networks | Medium | Legitimate one-time connections outnumber malicious ones |
| No content awareness | Medium | Cannot determine what was sent or received |
| No temporal context | Low | Cannot distinguish between old and recent singletons |
| No source grouping | Low | Cannot identify distributed scanning from related sources |
| External-only scope | Low | Internal singletons are not detected |

---

## Double-Tap Evasion

An attacker who connects to the same external destination more than `NoveltyMaxGlobalOccurrences` times defeats the detector for that destination. With the default threshold of 1, a second connection is enough to bypass detection (the "double-tap" evasion). This is trivially easy to implement.

**Mitigation:** Increase `NoveltyMaxGlobalOccurrences` to 2 or 3 to catch near-singletons. This increases both true and false positives and is most effective when combined with threat intelligence scoring to prioritize findings.

---

## High Noise Volume

On a busy network, singletons are extremely common. Every user visiting a unique website, every one-time API call, and every CDN edge node produces a singleton. The signal-to-noise ratio can be poor, making it difficult for analysts to identify the malicious singletons among thousands of benign ones.

**Mitigation:** Cross-reference with threat intelligence feeds to prioritize singletons to known-malicious IP ranges or suspicious ports. Apply allowlisting for known CDNs and popular services.

---

## No Content Awareness

The detector knows that host A connected to IP B on port C exactly once, but it doesn't know what was sent or received. The connection could be an empty probe, a DNS resolution, or a multi-megabyte data transfer.

**Mitigation:** Correlate with NetFlow data for volume analysis and with proxy logs for application-layer inspection. A singleton with a large byte count is much more suspicious than a singleton with zero data transfer.

---

## No Temporal Context

Singletons from the beginning of the log period and singletons from the end are treated identically. A connection to a suspicious IP that occurred yesterday is more operationally relevant than one that occurred six months ago.

**Mitigation:** Add time-decay weighting to singleton scores, or filter findings to only recent time windows. This is a natural enhancement for the risk escalation engine.

---

## External-Only Blind Spot

The detector only considers external destinations. Internal singletons (e.g., a compromised host probing an internal service once) are not detected.

**Mitigation:** Internal singletons are covered by the lateral movement detector (which watches for multi-host patterns) and the port scan detector (which watches for multi-port patterns). Single internal singletons are generally low-value for detection.

---

## Improvement Roadmap

| Priority | Improvement | Effort |
|---|---|---|
| High | Threat intelligence feed integration for singleton scoring | Medium |
| Medium | Known-service allowlisting (CDNs, popular APIs) | Medium |
| Medium | Time-decay scoring for recent vs. old singletons | Low |
| Low | Source-grouped analysis for distributed reconnaissance | Medium |
| Low | NetFlow volume correlation for singleton prioritization | Medium |

---

## Security Takeaways

- The double-tap evasion is the most impactful limitation — it's trivial for attackers and completely defeats detection
- High noise volume on busy networks means the detector is most valuable when combined with threat intelligence
- The external-only scope is intentional and appropriate — internal singletons are better served by other detectors
- The improvement roadmap focuses on reducing noise rather than expanding scope, reflecting the detector's role as a forensic lead generator
