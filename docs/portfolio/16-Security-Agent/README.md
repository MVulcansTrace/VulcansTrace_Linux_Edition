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

- **Natural-language intent parsing** — maps questions like "is my system secure?", "check my firewall", and "what ports are open?" into structured agent intents, plus deterministic follow-ups such as "what changed since the last audit?" and "what should I fix first?"
- **Live host scanning** — collects firewall, port, service, SSH daemon configuration, file permissions, kernel and system hardening parameters, user accounts, shadow entries, password aging, PAM configuration, interface, route, and connection state through local Linux commands
- **Data-source capability reporting** — records whether scanner inputs are available, unavailable, permission-limited, or intentionally not checked
- **Rule-based posture checks** — evaluates firewall, port, service, SSH, file permission, kernel hardening, and network rules without external AI dependencies
- **Role-aware local policy** — tunes selected rules for Workstation, Server, LabBox, Router, and DevMachine profiles with JSON overrides; the Avalonia UI includes a role dropdown for hot-swapping without code changes
- **Human-readable explanations** — turns failed rules into markdown-backed explanations with template variables
- **Stable finding fingerprints** — tracks the same posture issue across audit history, suppression matching, and evidence exports without depending on volatile wording or timestamps
- **Structured explanation sections** — separates what was found, why it matters, how to verify, preconditions, backup commands, suggested next action, rollback commands, confidence, and caveats
- **Copyable verification commands** — exposes only verification-section commands for clipboard copy and labels each with command safety and structural badges
- **Log-analysis bridge** — can include pasted firewall logs through the existing `SentryAnalyzer`
- **Evidence compatibility** — converts agent output back into `AnalysisResult` through `AgentReportGenerator`, preserves rule IDs, fingerprints, capability reports, and active suppression notes in evidence exports
- **Deterministic follow-up questions** — operates on the last audit result without re-running scans: changes since last audit, critical/high explanations, category filtering, prioritized remediation, interactive single-finding remediation, and suppressed listing
- **Configuration baseline & drift detection** — saves a "known good" baseline per intent, compares live audits against it, and reports new and worsened findings as drift with narrative summaries; preserves original finding details for lossless baseline display
- **Timed suppressions** — supports fingerprint-scoped 7-day, 30-day, 90-day, and permanent accepted-risk suppressions; expired suppressions stop applying immediately but remain reviewable for 30 days before pruning
- **Avalonia chat panel** — exposes chat, quick actions, grouped and filterable findings, selected-finding explanations, privilege warnings, rule coverage totals, persistent selectable audit history diff with narrative summaries, baseline set/drift/show actions, suppression review actions, cancellation, audit export, and guarded remediation preview export
- **Dual-layer CIS Benchmark mapping** — every rule maps to both CIS Controls v8 (organizational) and CIS Ubuntu 24.04 LTS Benchmark (technical) for audit-ready compliance traceability
- **CIS Compliance Scorecard** — formal pass/fail/warn per control family, overall percentage score, and trend over time, readable in 10 seconds by managers and auditors
- **Deterministic tests** — verifies intent parsing, scanner parser fixtures, rule behavior, explanations, reports, baseline store persistence, drift detection, agent orchestration, compliance scorecard computation, and CIS mapping flow-through across all execution paths

## Implementation Evidence

- [SecurityAgent.cs](../../../VulcansTrace.Linux.Agent/SecurityAgent.cs) — scanner/rule/explanation/log-analysis orchestration
- [IAgent.cs](../../../VulcansTrace.Linux.Agent/IAgent.cs) — public agent interface
- [QueryParser.cs](../../../VulcansTrace.Linux.Agent/Query/QueryParser.cs) — keyword-scored intent parser
- [ScanData.cs](../../../VulcansTrace.Linux.Agent/Scanners/ScanData.cs) — immutable scanner snapshot model
- [DataSourceCapability.cs](../../../VulcansTrace.Linux.Agent/Scanners/DataSourceCapability.cs) — scanner data-source availability model
- [IScanner.cs](../../../VulcansTrace.Linux.Agent/Scanners/IScanner.cs) — scanner contract and thread-safe `ScanDataBuilder`
- [FirewallScanner.cs](../../../VulcansTrace.Linux.Agent/Scanners/FirewallScanner.cs) — iptables/nftables posture collection
- [PortScanner.cs](../../../VulcansTrace.Linux.Agent/Scanners/PortScanner.cs) — listening-port collection
- [ServiceScanner.cs](../../../VulcansTrace.Linux.Agent/Scanners/ServiceScanner.cs) — systemd service collection
- [NetworkScanner.cs](../../../VulcansTrace.Linux.Agent/Scanners/NetworkScanner.cs) — interface, route, and connection collection
- [SshConfigScanner.cs](../../../VulcansTrace.Linux.Agent/Scanners/SshConfigScanner.cs) — SSH daemon configuration collection
- [FilePermissionScanner.cs](../../../VulcansTrace.Linux.Agent/Scanners/FilePermissionScanner.cs) — sensitive file and directory permission collection
- [FilesystemAuditScanner.cs](../../../VulcansTrace.Linux.Agent/Scanners/FilesystemAuditScanner.cs) — filesystem permission anomaly collection
- [KernelHardeningScanner.cs](../../../VulcansTrace.Linux.Agent/Scanners/KernelHardeningScanner.cs) — kernel and system hardening parameter collection
- [UserAccountScanner.cs](../../../VulcansTrace.Linux.Agent/Scanners/UserAccountScanner.cs) — local user account, shadow, password aging, and PAM configuration collection
- [SecurityRules](../../../VulcansTrace.Linux.Agent/Rules/SecurityRules) — firewall, network, service, port, SSH, file permission, filesystem audit, kernel hardening, and user account checks
- [Finding.cs](../../../VulcansTrace.Linux.Core/Finding.cs) — stable finding fingerprints
- [AuditDiffCalculator.cs](../../../VulcansTrace.Linux.Agent/Reports/AuditDiffCalculator.cs) — fingerprint-aware audit diffing
- [BaselineEntry.cs](../../../VulcansTrace.Linux.Agent/Baselines/BaselineEntry.cs) — baseline snapshot with original findings
- [IBaselineStore.cs](../../../VulcansTrace.Linux.Agent/Baselines/IBaselineStore.cs) — baseline storage contract
- [JsonFileBaselineStore.cs](../../../VulcansTrace.Linux.Agent/Baselines/JsonFileBaselineStore.cs) — persisted baseline store
- [DefaultRulePolicyProvider.cs](../../../VulcansTrace.Linux.Agent/Rules/DefaultRulePolicyProvider.cs) — built-in role defaults and user-policy merge behavior
- [JsonRulePolicyStore.cs](../../../VulcansTrace.Linux.Agent/Rules/JsonRulePolicyStore.cs) — local JSON policy persistence
- [ExplanationProvider.cs](../../../VulcansTrace.Linux.Agent/Explanations/ExplanationProvider.cs) — embedded markdown explanation loading
- [AgentReportGenerator.cs](../../../VulcansTrace.Linux.Agent/Reports/AgentReportGenerator.cs) — agent-to-analysis result adapter
- [AgentViewModel.cs](../../../VulcansTrace.Linux.Avalonia/ViewModels/AgentViewModel.cs) — chat panel ViewModel
- [AgentView.axaml](../../../VulcansTrace.Linux.Avalonia/AgentView.axaml) — chat panel UI
- [Agent tests](../../../VulcansTrace.Linux.Tests/Agent) — query, rule, explanation, report, and orchestration coverage
- [Evidence formatter tests](../../../VulcansTrace.Linux.Tests/Evidence) — rule ID preservation through CSV, JSON, Markdown, HTML, and STIX exports
