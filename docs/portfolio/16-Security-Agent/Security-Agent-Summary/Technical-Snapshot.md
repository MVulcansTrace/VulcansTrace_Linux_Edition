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
| Scanner types | 9: Firewall, Port, Service, Network, SSH, FilePermission, FilesystemAudit, KernelHardening, UserAccount |
| Rule categories | 9: Firewall, Port, Service, Network, SSH, FilePermission, FilesystemAudit, Kernel, UserAccount |
| Machine roles | 5: Workstation, Server, LabBox, Router, DevMachine |
| Policy persistence | JSON overrides in `~/.config/VulcansTrace/policy.json` |
| Baseline persistence | JSON in `~/.config/VulcansTrace/baselines.json` |
| Data-source capability states | Available, Unavailable, PermissionLimited, Unknown |
| Finding identity | Stable SHA-256-based fingerprints for audit diffing, suppression matching, baseline tracking, and evidence traceability |
| Agent intents | 21: FullAudit, FirewallCheck, NetworkCheck, ServiceCheck, PortCheck, SshCheck, FilePermissionCheck, FilesystemAuditCheck, KernelCheck, UserAccountCheck, ExplainFinding, ShowChanges, ExplainCritical, FilterCategory, PrioritizeRemediation, FixFinding, ListSuppressed, SetBaseline, CheckDrift, ShowBaseline, Help |
| CIS mapping coverage | 51 / 51 rules (100%): dual-layer CIS Controls v8 + CIS Ubuntu 24.04 LTS Benchmark |
| CIS mapping fields | ControlId, ControlName, WhyItMatters, BenchmarkReference |
| Target references | Rule IDs and category keywords extracted from explanation queries |
| Explanation templates | 7 embedded markdown files |
| UI integration | Collapsible Avalonia Security Agent chat panel with quick actions, grouped and filterable findings, rule coverage totals, selection-aware explanations, safety-labeled and structurally badged verification commands, timed suppressions, persistent selectable audit history diff with narrative summaries, privilege warnings, audit export, guarded remediation export, and interactive single-finding remediation cards with preconditions, backup/apply/rollback/verification commands and safety badges |
| Test files | Agent, scanner parser, Avalonia ViewModel, and evidence formatter coverage |

---

## Why It Matters

- **Bridges raw analysis and analyst questions** — the user can ask "what ports are open?" instead of choosing a detector manually
- **Adds live host posture** — VulcansTrace can now inspect the system state, not only pasted firewall logs
- **Shows audit visibility** — capability reports make it clear when scanner evidence came from available, unavailable, or permission-limited commands
- **Reduces false positives with explicit local context** — Workstation, Server, LabBox, Router, and DevMachine profiles tune selected rules without weakening the global rule catalog
- **Keeps trust high** — deterministic rules and markdown explanations make findings auditable
- **Stays local-first** — no external AI call is required to answer security questions
- **Reuses existing evidence infrastructure** — agent findings can be merged into `AnalysisResult` for reporting workflows, with rule IDs, fingerprints, active suppression notes, and CIS Benchmark mappings preserved in exported evidence
- **Dual-layer compliance context** — every rule maps to both CIS Controls v8 (organizational) and CIS Ubuntu 24.04 LTS Benchmark (technical), giving auditors precise 1:1 traceability from a finding to the exact benchmark section it validates

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
- [FilePermissionScanner.cs](../../../../VulcansTrace.Linux.Agent/Scanners/FilePermissionScanner.cs) — sensitive file and directory permission collection
- [FilesystemAuditScanner.cs](../../../../VulcansTrace.Linux.Agent/Scanners/FilesystemAuditScanner.cs) — filesystem permission anomaly collection
- [KernelHardeningScanner.cs](../../../../VulcansTrace.Linux.Agent/Scanners/KernelHardeningScanner.cs) — kernel and system hardening parameter collection
- [UserAccountScanner.cs](../../../../VulcansTrace.Linux.Agent/Scanners/UserAccountScanner.cs) — local user account, shadow, password aging, and PAM configuration collection
- [FirewallRules.cs](../../../../VulcansTrace.Linux.Agent/Rules/SecurityRules/FirewallRules.cs) — firewall posture rules
- [PortRules.cs](../../../../VulcansTrace.Linux.Agent/Rules/SecurityRules/PortRules.cs) — exposed-port rules
- [ServiceRules.cs](../../../../VulcansTrace.Linux.Agent/Rules/SecurityRules/ServiceRules.cs) — service posture rules
- [NetworkRules.cs](../../../../VulcansTrace.Linux.Agent/Rules/SecurityRules/NetworkRules.cs) — routing and connection rules
- [FilePermissionRules.cs](../../../../VulcansTrace.Linux.Agent/Rules/SecurityRules/FilePermissionRules.cs) — file permission posture rules
- [FilesystemAuditRules.cs](../../../../VulcansTrace.Linux.Agent/Rules/SecurityRules/FilesystemAuditRules.cs) — filesystem audit posture rules
- [DefaultRulePolicyProvider.cs](../../../../VulcansTrace.Linux.Agent/Rules/DefaultRulePolicyProvider.cs) — built-in role defaults and local override merge behavior
- [JsonRulePolicyStore.cs](../../../../VulcansTrace.Linux.Agent/Rules/JsonRulePolicyStore.cs) — persisted rule policy store
- [Finding.cs](../../../../VulcansTrace.Linux.Core/Finding.cs) — stable finding identity and fingerprints
- [AuditDiffCalculator.cs](../../../../VulcansTrace.Linux.Agent/Reports/AuditDiffCalculator.cs) — fingerprint-aware audit comparison
- [BaselineEntry.cs](../../../../VulcansTrace.Linux.Agent/Baselines/BaselineEntry.cs) — baseline snapshot with original findings
- [IBaselineStore.cs](../../../../VulcansTrace.Linux.Agent/Baselines/IBaselineStore.cs) — baseline storage contract
- [JsonFileBaselineStore.cs](../../../../VulcansTrace.Linux.Agent/Baselines/JsonFileBaselineStore.cs) — persisted baseline store
- [SuppressionEntry.cs](../../../../VulcansTrace.Linux.Agent/Rules/SuppressionEntry.cs) — fingerprint-scoped accepted-risk entries
- [AgentViewModel.cs](../../../../VulcansTrace.Linux.Avalonia/ViewModels/AgentViewModel.cs) — UI command flow
- [SecurityAgentTests.cs](../../../../VulcansTrace.Linux.Tests/Agent/SecurityAgentTests.cs) — orchestration tests
- [ScannerParserFixtureTests.cs](../../../../VulcansTrace.Linux.Tests/Agent/ScannerParserFixtureTests.cs) — realistic command-output parser fixtures

---

## Current Status

This is a v1 local security assistant. It can scan, evaluate, report data-source capability status, tune selected rules by machine role and local JSON policy, explain selected or referenced findings, answer deterministic follow-up questions (changes since last audit, critical explanations, category filtering, prioritized remediation, interactive single-finding remediation, suppressed listing) without re-running scans, group and filter results in the UI, surface privilege-limited scans, preserve and expire fingerprint-scoped accepted-risk suppressions, keep recently expired suppressions reviewable for 30 days, compare selected audits with fingerprint matching and a deterministic change narrative, snapshot known-good configuration baselines per intent, detect drift against those baselines with new and worsened findings surfaced as actionable results, display baselines with original finding details preserved, export guarded remediation previews with explicit rollback requirements for risky commands, guide users through step-by-step interactive remediation for individual findings with safety-classified commands and rollback visibility, and export agent audits with capability and active suppression notes through the shared evidence workflow. It is not an LLM-backed conversational agent. The next high-value improvements are a UI role selector, broader distro-specific parser fixtures, a "Fix Selected" quick-action button, and reminder surfaces for upcoming suppression reviews.
