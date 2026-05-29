> **1 page:** the Security Agent subsystem, why it matters, and where the proof lives in the codebase.

---

## Implementation Overview

The Security Agent is a local assistant layer on top of VulcansTrace. It does not replace the log-analysis engine; it adds a host-posture audit path that can answer natural-language questions and inspect the live Linux system. The main orchestrator, `SecurityAgent`, parses the user's query into an `AgentQuery`, runs local scanners, evaluates rules, converts failed checks into `Finding` records, fills human-readable markdown explanations, caches findings by originating rule ID for follow-up questions, and optionally includes firewall-log analysis through `SentryAnalyzer`.

The subsystem is deliberately deterministic and explainable. Each result can be traced to a scanner, a rule, and an explanation template rather than to opaque model output.

---

## Key Metrics

| Metric | Value |
| --- | --- |
| Agent project | `VulcansTrace.Linux.Agent` |
| Scanner types | 4: Firewall, Port, Service, Network |
| Rule categories | 4: Firewall, Port, Service, Network |
| Agent intents | 7: FullAudit, FirewallCheck, NetworkCheck, ServiceCheck, PortCheck, ExplainFinding, Help |
| Target references | Rule IDs and category keywords extracted from explanation queries |
| Explanation templates | 4 embedded markdown files |
| UI integration | Collapsible Avalonia Security Agent chat panel with quick actions, grouped and filterable findings, selection-aware explanations, safety-labeled verification commands, timed suppressions, selectable audit history diff, privilege warnings, audit export, and remediation export |
| Test files | Agent, scanner parser, Avalonia ViewModel, and evidence formatter coverage |

---

## Why It Matters

- **Bridges raw analysis and analyst questions** — the user can ask "what ports are open?" instead of choosing a detector manually
- **Adds live host posture** — VulcansTrace can now inspect the system state, not only pasted firewall logs
- **Keeps trust high** — deterministic rules and markdown explanations make findings auditable
- **Stays local-first** — no external AI call is required to answer security questions
- **Reuses existing evidence infrastructure** — agent findings can be merged into `AnalysisResult` for reporting workflows, with rule IDs preserved in exported evidence

---

## Key Evidence

- [SecurityAgent.cs](../../../../VulcansTrace.Linux.Agent/SecurityAgent.cs) — orchestration
- [QueryParser.cs](../../../../VulcansTrace.Linux.Agent/Query/QueryParser.cs) — intent parsing
- [IScanner.cs](../../../../VulcansTrace.Linux.Agent/Scanners/IScanner.cs) — thread-safe scanner aggregation
- [FirewallScanner.cs](../../../../VulcansTrace.Linux.Agent/Scanners/FirewallScanner.cs) — firewall collection
- [PortScanner.cs](../../../../VulcansTrace.Linux.Agent/Scanners/PortScanner.cs) — listening-port collection
- [ServiceScanner.cs](../../../../VulcansTrace.Linux.Agent/Scanners/ServiceScanner.cs) — service collection
- [NetworkScanner.cs](../../../../VulcansTrace.Linux.Agent/Scanners/NetworkScanner.cs) — interface, route, connection collection
- [FirewallRules.cs](../../../../VulcansTrace.Linux.Agent/Rules/SecurityRules/FirewallRules.cs) — firewall posture rules
- [PortRules.cs](../../../../VulcansTrace.Linux.Agent/Rules/SecurityRules/PortRules.cs) — exposed-port rules
- [ServiceRules.cs](../../../../VulcansTrace.Linux.Agent/Rules/SecurityRules/ServiceRules.cs) — service posture rules
- [NetworkRules.cs](../../../../VulcansTrace.Linux.Agent/Rules/SecurityRules/NetworkRules.cs) — routing and connection rules
- [AgentViewModel.cs](../../../../VulcansTrace.Linux.Avalonia/ViewModels/AgentViewModel.cs) — UI command flow
- [SecurityAgentTests.cs](../../../../VulcansTrace.Linux.Tests/Agent/SecurityAgentTests.cs) — orchestration tests
- [ScannerParserFixtureTests.cs](../../../../VulcansTrace.Linux.Tests/Agent/ScannerParserFixtureTests.cs) — realistic command-output parser fixtures

---

## Current Status

This is a v1 local security assistant. It can scan, evaluate, explain selected or referenced findings, group and filter results in the UI, surface privilege-limited scans, preserve and expire accepted-risk suppressions, keep recently expired suppressions reviewable for 30 days, compare selected audits, export safety-labeled remediation previews, and export agent audits with active suppression notes through the shared evidence workflow. It is not an LLM-backed conversational agent. The next high-value improvements are broader distro-specific parser fixtures, richer follow-up explanation flows, and reminder surfaces for upcoming suppression reviews.
