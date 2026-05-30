# Security Agent

The Security Agent subsystem adds a local, deterministic security assistant to VulcansTrace Linux Edition. It accepts plain-English questions, scans live Linux host state, evaluates role-aware posture rules, explains findings with markdown templates, and bridges those results back into the existing analysis and evidence model.

Documentation is organized for two audiences:

- **Recruiters and hiring managers** who need a fast, high-level view of what the agent does and why it matters
- **Technical reviewers** who want to inspect the actual implementation choices, scanner pipeline, rule behavior, and test evidence

## Start Here

- [Technical Snapshot](./Security-Agent-Summary/Technical-Snapshot.md) — one-page overview of the subsystem, architecture, and proof points
- [Quick Reference](./Security-Agent-Summary/Quick-Reference.md) — intents, scanners, rules, UI behavior, and limitations at a glance
- [Design Decisions](./Security-Agent-In-Depth/Design-Decisions.md) — rationale for deterministic local analysis, scanner/rule separation, role-aware policy, and explanation templates

## System Capabilities

- **Natural-language intent parsing** — maps questions like "is my system secure?", "check my firewall", and "what ports are open?" into structured agent intents
- **Live host scanning** — collects firewall, port, service, interface, route, and connection state through local Linux commands
- **Rule-based posture checks** — evaluates firewall, port, service, and network rules without external AI dependencies
- **Role-aware local policy** — tunes selected rules for Workstation, Server, LabBox, Router, and DevMachine profiles with JSON overrides
- **Human-readable explanations** — turns failed rules into markdown-backed explanations with template variables
- **Stable finding fingerprints** — tracks the same posture issue across audit history, suppression matching, and evidence exports without depending on volatile wording or timestamps
- **Structured explanation sections** — separates what was found, why it matters, how to verify, preconditions, backup commands, suggested next action, rollback commands, confidence, and caveats
- **Copyable verification commands** — exposes only verification-section commands for clipboard copy and labels each with command safety and structural badges
- **Log-analysis bridge** — can include pasted firewall logs through the existing `SentryAnalyzer`
- **Evidence compatibility** — converts agent output back into `AnalysisResult` through `AgentReportGenerator`, preserves rule IDs and fingerprints, and includes active suppression notes in evidence exports
- **Timed suppressions** — supports fingerprint-scoped 7-day, 30-day, 90-day, and permanent accepted-risk suppressions; expired suppressions stop applying immediately but remain reviewable for 30 days before pruning
- **Avalonia chat panel** — exposes chat, quick actions, grouped and filterable findings, selected-finding explanations, privilege warnings, rule coverage totals, persistent selectable audit history diff with narrative summaries, suppression review actions, cancellation, audit export, and guarded remediation preview export
- **Deterministic tests** — verifies intent parsing, scanner parser fixtures, rule behavior, explanations, reports, and agent orchestration

## Implementation Evidence

- [SecurityAgent.cs](../../../VulcansTrace.Linux.Agent/SecurityAgent.cs) — scanner/rule/explanation/log-analysis orchestration
- [IAgent.cs](../../../VulcansTrace.Linux.Agent/IAgent.cs) — public agent interface
- [QueryParser.cs](../../../VulcansTrace.Linux.Agent/Query/QueryParser.cs) — keyword-scored intent parser
- [ScanData.cs](../../../VulcansTrace.Linux.Agent/Scanners/ScanData.cs) — immutable scanner snapshot model
- [IScanner.cs](../../../VulcansTrace.Linux.Agent/Scanners/IScanner.cs) — scanner contract and thread-safe `ScanDataBuilder`
- [FirewallScanner.cs](../../../VulcansTrace.Linux.Agent/Scanners/FirewallScanner.cs) — iptables/nftables posture collection
- [PortScanner.cs](../../../VulcansTrace.Linux.Agent/Scanners/PortScanner.cs) — listening-port collection
- [ServiceScanner.cs](../../../VulcansTrace.Linux.Agent/Scanners/ServiceScanner.cs) — systemd service collection
- [NetworkScanner.cs](../../../VulcansTrace.Linux.Agent/Scanners/NetworkScanner.cs) — interface, route, and connection collection
- [SecurityRules](../../../VulcansTrace.Linux.Agent/Rules/SecurityRules) — firewall, network, service, and port checks
- [Finding.cs](../../../VulcansTrace.Linux.Core/Finding.cs) — stable finding fingerprints
- [AuditDiffCalculator.cs](../../../VulcansTrace.Linux.Agent/Reports/AuditDiffCalculator.cs) — fingerprint-aware audit diffing
- [DefaultRulePolicyProvider.cs](../../../VulcansTrace.Linux.Agent/Rules/DefaultRulePolicyProvider.cs) — built-in role defaults and user-policy merge behavior
- [JsonRulePolicyStore.cs](../../../VulcansTrace.Linux.Agent/Rules/JsonRulePolicyStore.cs) — local JSON policy persistence
- [ExplanationProvider.cs](../../../VulcansTrace.Linux.Agent/Explanations/ExplanationProvider.cs) — embedded markdown explanation loading
- [AgentReportGenerator.cs](../../../VulcansTrace.Linux.Agent/Reports/AgentReportGenerator.cs) — agent-to-analysis result adapter
- [AgentViewModel.cs](../../../VulcansTrace.Linux.Avalonia/ViewModels/AgentViewModel.cs) — chat panel ViewModel
- [AgentView.axaml](../../../VulcansTrace.Linux.Avalonia/AgentView.axaml) — chat panel UI
- [Agent tests](../../../VulcansTrace.Linux.Tests/Agent) — query, rule, explanation, report, and orchestration coverage
- [Evidence formatter tests](../../../VulcansTrace.Linux.Tests/Evidence) — rule ID preservation through CSV, JSON, Markdown, HTML, and STIX exports
