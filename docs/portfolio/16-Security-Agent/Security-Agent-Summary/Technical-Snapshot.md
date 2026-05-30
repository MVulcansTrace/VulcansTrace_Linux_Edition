> **1 page:** the Security Agent subsystem, why it matters, and where the proof lives in the codebase.

---

## Implementation Overview

The Security Agent is a local assistant layer on top of VulcansTrace. It does not replace the log-analysis engine; it adds a host-posture audit path that can answer natural-language questions and inspect the live Linux system. The main orchestrator, `SecurityAgent`, parses the user's query into an `AgentQuery`, runs local scanners, records data-source capabilities, resolves role-aware policy, evaluates rules, converts failed checks into fingerprinted `Finding` records, fills human-readable markdown explanations, caches findings by originating rule ID for follow-up questions, and optionally includes firewall-log analysis through `SentryAnalyzer`.

The subsystem is deliberately deterministic and explainable. Each result can be traced to a scanner, a rule, and an explanation template rather than to opaque model output.

---

## Key Metrics

| Metric | Value |
| --- | --- |
| Agent project | `VulcansTrace.Linux.Agent` |
| Scanner types | 4: Firewall, Port, Service, Network |
| Rule categories | 4: Firewall, Port, Service, Network |
| Machine roles | 5: Workstation, Server, LabBox, Router, DevMachine |
| Policy persistence | JSON overrides in `~/.config/VulcansTrace/policy.json` |
| Data-source capability states | Available, Unavailable, PermissionLimited, Unknown |
| Finding identity | Stable SHA-256-based fingerprints for audit diffing, suppression matching, and evidence traceability |
| Agent intents | 7: FullAudit, FirewallCheck, NetworkCheck, ServiceCheck, PortCheck, ExplainFinding, Help |
| Target references | Rule IDs and category keywords extracted from explanation queries |
| Explanation templates | 4 embedded markdown files |
| UI integration | Collapsible Avalonia Security Agent chat panel with quick actions, grouped and filterable findings, rule coverage totals, selection-aware explanations, safety-labeled and structurally badged verification commands, timed suppressions, persistent selectable audit history diff with narrative summaries, privilege warnings, audit export, and guarded remediation export |
| Test files | Agent, scanner parser, Avalonia ViewModel, and evidence formatter coverage |

---

## Why It Matters

- **Bridges raw analysis and analyst questions** — the user can ask "what ports are open?" instead of choosing a detector manually
- **Adds live host posture** — VulcansTrace can now inspect the system state, not only pasted firewall logs
- **Shows audit visibility** — capability reports make it clear when scanner evidence came from available, unavailable, or permission-limited commands
- **Reduces false positives with explicit local context** — Workstation, Server, LabBox, Router, and DevMachine profiles tune selected rules without weakening the global rule catalog
- **Keeps trust high** — deterministic rules and markdown explanations make findings auditable
- **Stays local-first** — no external AI call is required to answer security questions
- **Reuses existing evidence infrastructure** — agent findings can be merged into `AnalysisResult` for reporting workflows, with rule IDs, fingerprints, and active suppression notes preserved in exported evidence

---

## Key Evidence

- [SecurityAgent.cs](../../../../VulcansTrace.Linux.Agent/SecurityAgent.cs) — orchestration
- [QueryParser.cs](../../../../VulcansTrace.Linux.Agent/Query/QueryParser.cs) — intent parsing
- [IScanner.cs](../../../../VulcansTrace.Linux.Agent/Scanners/IScanner.cs) — thread-safe scanner aggregation
- [DataSourceCapability.cs](../../../../VulcansTrace.Linux.Agent/Scanners/DataSourceCapability.cs) — data-source availability and permission status
- [FirewallScanner.cs](../../../../VulcansTrace.Linux.Agent/Scanners/FirewallScanner.cs) — firewall collection
- [PortScanner.cs](../../../../VulcansTrace.Linux.Agent/Scanners/PortScanner.cs) — listening-port collection
- [ServiceScanner.cs](../../../../VulcansTrace.Linux.Agent/Scanners/ServiceScanner.cs) — service collection
- [NetworkScanner.cs](../../../../VulcansTrace.Linux.Agent/Scanners/NetworkScanner.cs) — interface, route, connection collection
- [FirewallRules.cs](../../../../VulcansTrace.Linux.Agent/Rules/SecurityRules/FirewallRules.cs) — firewall posture rules
- [PortRules.cs](../../../../VulcansTrace.Linux.Agent/Rules/SecurityRules/PortRules.cs) — exposed-port rules
- [ServiceRules.cs](../../../../VulcansTrace.Linux.Agent/Rules/SecurityRules/ServiceRules.cs) — service posture rules
- [NetworkRules.cs](../../../../VulcansTrace.Linux.Agent/Rules/SecurityRules/NetworkRules.cs) — routing and connection rules
- [DefaultRulePolicyProvider.cs](../../../../VulcansTrace.Linux.Agent/Rules/DefaultRulePolicyProvider.cs) — built-in role defaults and local override merge behavior
- [JsonRulePolicyStore.cs](../../../../VulcansTrace.Linux.Agent/Rules/JsonRulePolicyStore.cs) — persisted rule policy store
- [Finding.cs](../../../../VulcansTrace.Linux.Core/Finding.cs) — stable finding identity and fingerprints
- [AuditDiffCalculator.cs](../../../../VulcansTrace.Linux.Agent/Reports/AuditDiffCalculator.cs) — fingerprint-aware audit comparison
- [SuppressionEntry.cs](../../../../VulcansTrace.Linux.Agent/Rules/SuppressionEntry.cs) — fingerprint-scoped accepted-risk entries
- [AgentViewModel.cs](../../../../VulcansTrace.Linux.Avalonia/ViewModels/AgentViewModel.cs) — UI command flow
- [SecurityAgentTests.cs](../../../../VulcansTrace.Linux.Tests/Agent/SecurityAgentTests.cs) — orchestration tests
- [ScannerParserFixtureTests.cs](../../../../VulcansTrace.Linux.Tests/Agent/ScannerParserFixtureTests.cs) — realistic command-output parser fixtures

---

## Current Status

This is a v1 local security assistant. It can scan, evaluate, report data-source capability status, tune selected rules by machine role and local JSON policy, explain selected or referenced findings, group and filter results in the UI, surface privilege-limited scans, preserve and expire fingerprint-scoped accepted-risk suppressions, keep recently expired suppressions reviewable for 30 days, compare selected audits with fingerprint matching and a deterministic change narrative, export guarded remediation previews with explicit rollback requirements for risky commands, and export agent audits with capability and active suppression notes through the shared evidence workflow. It is not an LLM-backed conversational agent. The next high-value improvements are a UI role selector, broader distro-specific parser fixtures, richer follow-up explanation flows, and reminder surfaces for upcoming suppression reviews.
