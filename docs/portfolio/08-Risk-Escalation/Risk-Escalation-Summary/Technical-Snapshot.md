# Risk Escalation — Technical Snapshot

A one-page overview of how VulcansTrace Linux Edition correlates individual detector findings into higher-confidence host risk assessments.

---

## What It Does

The risk escalation subsystem receives findings from all detectors, groups them by source host, checks whether any combination of categories on the same host matches a known high-severity correlation rule within the time window, and upgrades qualifying findings to Critical severity. It runs before Beaconing/C2 deduplication, severity filtering, and the per-category noise budget in the `SentryAnalyzer` pipeline.

The subsystem also detects **critical attack chains** — Beaconing → LateralMovement → PrivilegeEscalation triplets on the same host — which trigger the Automated Incident Response Playbooks layer for active defense.

---

## How It Works

1. **Group by host** — findings are partitioned by `SourceHost` using `GroupBy`
2. **Build category set** — a case-insensitive `HashSet<string>` of all categories present on that host
3. **Evaluate correlation rules** — three category pairs are checked against the host's category set and then gated by a 24-hour time-range correlation check
4. **Escalate** — if any rule fires, findings whose categories participate in the matched rule and are below Critical are re-created with `Severity = Critical` via the C# `with` expression on the `Finding` record. A `Cross-detector correlation` evidence signal is appended and confidence is recalculated via `FindingConfidenceCalculator`. Findings whose categories are not part of the matched rule are passed through unchanged.
5. **Pass through** — findings that do not trigger a rule are added to the result unchanged

---

## Correlation Rules

| Rule | Categories | Interpretation |
|------|-----------|----------------|
| Beaconing + LateralMovement | C2 callback + internal pivoting | Compromised host is both phoning home and spreading |
| FlagAnomaly + PortScan | Evasion + reconnaissance | Attacker is probing while manipulating TCP flags to evade IDS |
| MacSpoofing + InterfaceHopping | Network-control bypass | Attacker is rotating MAC addresses and interfaces to avoid tracking |

---

## Key Metrics

| Metric | Value |
|--------|-------|
| Correlation rules | 3 pair rules + 1 critical triplet rule |
| Detection layers | 3 (baseline, Linux deep inspection, advanced) |
| Parse error cap | 500 |
| Immutable escalation | Yes — `with` expression on record |
| Fault isolation | Per-detector try/catch |
| Critical chain → countermeasure | Yes — auto-generated iptables + auditd commands |
| Integration test count | 15+ across SentryAnalyzerTests and RealWorldAttackScenarioTests |

---

## Where the Proof Lives

| Artifact | Location |
|----------|----------|
| Correlation engine | [RiskEscalator.cs](../../../../VulcansTrace.Linux.Engine/RiskEscalator.cs) |
| Critical chain detection | [TraceMapCorrelator.cs](../../../../VulcansTrace.Linux.Engine/TraceMapCorrelator.cs) |
| Countermeasure generation | [RemediationPlanBuilder.cs](../../../../VulcansTrace.Linux.Agent/Reports/RemediationPlanBuilder.cs) |
| Pipeline orchestrator | [SentryAnalyzer.cs](../../../../VulcansTrace.Linux.Engine/SentryAnalyzer.cs) |
| Profile configuration | [AnalysisProfile.cs](../../../../VulcansTrace.Linux.Engine/AnalysisProfile.cs) |
| Finding record | [Finding.cs](../../../../VulcansTrace.Linux.Core/Finding.cs) |
| Severity enum | [Severity.cs](../../../../VulcansTrace.Linux.Core/Severity.cs) |
| Integration tests | [SentryAnalyzerTests.cs](../../../../VulcansTrace.Linux.Tests/Integration/SentryAnalyzerTests.cs) |
| Attack scenario tests | [RealWorldAttackScenarioTests.cs](../../../../VulcansTrace.Linux.Tests/Integration/RealWorldAttackScenarioTests.cs) |
| Critical chain tests | [TraceMapCorrelatorTests.cs](../../../../VulcansTrace.Linux.Tests/Engine/TraceMapCorrelatorTests.cs) |
| Countermeasure tests | [RemediationPlanBuilderTests.cs](../../../../VulcansTrace.Linux.Tests/Agent/RemediationPlanBuilderTests.cs) |

---

## Security Takeaways

- Individual detectors produce isolated findings; correlation is what turns them into host-level risk assessments
- Escalation is immutable — the original severity is preserved in any finding that does not match a rule, and escalated findings are new record copies rather than mutations
- The three correlation rules are grounded in attacker behavior patterns documented in the MITRE ATT&CK framework (see [MITRE ATT&CK Mapping](../Risk-Escalation-In-Depth/MITRE-ATTACK-Mapping.md))
- Fault isolation means a failing detector cannot prevent escalation of findings from healthy detectors
