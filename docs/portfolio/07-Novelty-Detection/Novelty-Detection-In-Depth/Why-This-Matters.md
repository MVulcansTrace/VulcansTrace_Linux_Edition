# Novelty Detection — Why This Matters

## Security Problem

Volume-based detectors (flood, port scan, lateral movement) are excellent at catching attackers who generate lots of traffic. But some of the most dangerous attack activities produce very little network footprint: a single reconnaissance probe to test if a service is reachable, a one-time exfiltration test to verify a data channel works, or a brief connection to a newly provisioned C2 server before the attacker switches to a regular beaconing pattern.

These "singletons" — external destinations that appear exactly once in the entire log dataset — are invisible to threshold-based detection. A port scan detector looking for 20+ ports won't fire on one port. A flood detector looking for 100+ events won't fire on one event. Yet that single connection could be the first indicator of an imminent attack or an ongoing low-and-slow compromise.

The novelty detector fills this gap by systematically identifying every external destination that was contacted no more than `NoveltyMaxGlobalOccurrences` times (default 1, i.e. strict singletons), providing leads that volume-based detectors deliberately ignore.

---

## Implementation Overview

The detector operates on pre-normalized `UnifiedEvent` records through a two-pass pipeline:

1. **Filter** — retain only events with external destinations
2. **Pass 1 — Build frequency** — group by (DestIP, DestPort) and count occurrences
3. **Pass 2 — Extract singletons** — iterate events again and flag those with frequency == 1

The two-pass design is mandatory: a single-pass approach cannot determine whether the current event is a singleton until all events have been processed.

---

## Operational Benefits

| Benefit | Description |
|---|---|
| Reconnaissance detection | Catches single-probe port scans that fall below scan detection thresholds |
| Exfiltration testing | Flags one-time test connections to external drop sites |
| New infrastructure discovery | Identifies connections to previously unseen external endpoints |
| Deep forensic coverage | Provides investigation leads that complement volume-based detectors |
| Profile-aware activation | Disabled in low-sensitivity mode to avoid noise; enabled for thorough analysis |

---

## Security Principles Applied

| Principle | Application |
|---|---|
| Defense in depth | Covers the attack surface that volume-based detectors leave open |
| Least privilege | Low severity reflects the uncertainty of singleton detection |
| Separation of concerns | Complements but does not duplicate flood, scan, or beaconing detection |
| Conservative alerting | Low severity prevents singletons from triggering high-priority response workflows |
| Configurable rarity | `NoveltyMaxGlobalOccurrences` controls how many occurrences still count as novel (default 1) |

---

## Implementation Evidence

- [NoveltyDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/NoveltyDetector.cs) — two-pass singleton detector (83 lines)
- [NoveltyDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/Baseline/NoveltyDetectorTests.cs) — test suite (74 lines)

---

> **Elevator Pitch:** While other detectors watch for loud attacks, the novelty detector watches for the quiet ones — that single connection to an external IP that was never seen before and never seen again. It's the detector that catches the attacker testing the waters before they commit to the real attack.

---

## Security Takeaways

- Singleton detection fills the coverage gap that volume-based detectors leave open
- The two-pass algorithm is the simplest correct approach — frequency must be fully computed before singletons can be identified
- Low severity reflects appropriate uncertainty — singletons are leads, not conclusions
- Disabled in Low profile acknowledges the noise inherent in singleton detection on large networks
- The 83-line implementation demonstrates that effective security tooling can be minimal and auditable
