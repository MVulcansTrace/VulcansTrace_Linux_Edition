# Novelty Detection

The novelty detector flags external destinations that appear only once in the log data — catching reconnaissance probes, one-time exfiltration tests, and connections to newly compromised infrastructure that volume-based detectors would miss.

Documentation is organized for two audiences:

- **Recruiters and hiring managers** who need a fast, high-level view of what this subsystem does and why it matters
- **Technical reviewers** who want to inspect the actual implementation choices, algorithmic details, and test evidence

## Start Here

- [Technical Snapshot](./Novelty-Detection-Summary/Technical-Snapshot.md) — one-page overview of the subsystem, its design, and where the proof lives
- [Quick Reference](./Novelty-Detection-Summary/Quick-Reference.md) — algorithm stages, configuration, output schema, and thresholds at a glance
- [Why This Matters](./Novelty-Detection-In-Depth/Why-This-Matters.md) — the security problem this detector solves and the principles behind it
- [Detection Algorithm](./Novelty-Detection-In-Depth/Core-Logic-Breakdown/Detection-Algorithm.md) — step-by-step walkthrough of the two-pass singleton detection pipeline
- [Design Decisions](./Novelty-Detection-In-Depth/Design-Decisions.md) — rationale for key architectural choices
- [Code Patterns](./Novelty-Detection-In-Depth/Code-Patterns.md) — recurring implementation patterns and how they support reliability
- [Attack Scenario](./Novelty-Detection-In-Depth/Attack-Scenario.md) — worked example showing a novel connection being detected
- [Evasion and Limitations](./Novelty-Detection-In-Depth/Evasion-and-Limitations.md) — known weaknesses and the improvement roadmap
- [MITRE ATT&CK Mapping](./Novelty-Detection-In-Depth/MITRE-ATTACK-Mapping.md) — technique and tactic mapping with detection gaps

## System Capabilities

- **Two-pass rarity detection** — first pass counts (DestIP, DestPort) frequencies, second pass flags events with count ≤ `NoveltyMaxGlobalOccurrences` (default 1) and groups novel destinations by source IP
- **External-destination focus** — only considers outbound connections to public IP addresses
- **Source-grouped findings** — each source IP produces one finding with a comma-separated target list (up to 5 entries + `"..."`) and count-based description
- **Low-severity findings** — deliberately conservative; singletons are suggestive but not conclusive evidence of malicious activity
- **Profile-controlled enablement** — disabled in Low profile, enabled in Medium and High profiles
- **Configurable rarity threshold** — `NoveltyMaxGlobalOccurrences` controls how many occurrences still count as "novel" (default 1, i.e. strict singletons)

## Implementation Evidence

- [NoveltyDetector.cs](../../../VulcansTrace.Linux.Engine/Detectors/NoveltyDetector.cs) — two-pass singleton detector (83 lines)
- [NoveltyDetectorTests.cs](../../../VulcansTrace.Linux.Tests/Detectors/Baseline/NoveltyDetectorTests.cs) — baseline test coverage (74 lines)
