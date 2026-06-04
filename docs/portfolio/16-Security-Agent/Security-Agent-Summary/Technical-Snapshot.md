> **1 page:** the Security Agent subsystem, why it matters, and where the proof lives in the codebase.

---

## Implementation Overview

The Security Agent is a local assistant layer on top of VulcansTrace. It does not replace the log-analysis engine; it adds a host-posture audit path that can answer natural-language questions and inspect the live Linux system. `SecurityAgent` is now the entry point that parses the user's query into an `AgentQuery` and delegates the pipeline to focused services.

`ScannerCoordinator` runs local scanners, `RuleEvaluationService` resolves role-aware policy and evaluates rules, and `FindingAssemblyService` converts failed checks into fingerprinted `Finding` records. `AgentResultComposer` formats summaries and capability reports, `AgentLogAnalysisService` optionally includes firewall-log analysis through `SentryAnalyzer`, and `AgentResultFinalizer` attaches scorecards while updating `AgentAuditState` for follow-up questions.

The subsystem is deliberately deterministic and explainable. Each result can be traced to a scanner, a rule, and an explanation template rather than to opaque model output.

---

## Key Metrics

| Metric | Value |
| --- | --- |
| Agent project | `VulcansTrace.Linux.Agent` |
| Scanner types | 15: Firewall, Port, Service, Network, SSH, FilePermission, FilesystemAudit, KernelHardening, UserAccount, LoggingAudit, CronJob, PackageVulnerability, Container, Kubernetes, FileHash |
| Rule categories | 15: Firewall, Port, Service, Network, SSH, FilePermission, FilesystemAudit, Kernel, UserAccount, Logging, CronJob, PackageVulnerability, Container, Kubernetes, ThreatIntel |
| Machine roles | 5: Workstation, Server, LabBox, Router, DevMachine |
| Policy persistence | JSON overrides in `~/.config/VulcansTrace/policy.json` |
| Baseline persistence | JSON in `~/.config/VulcansTrace/baselines.json` |
| Data-source capability states | Available, Unavailable, PermissionLimited, Unknown |
| Finding identity | Stable SHA-256-based fingerprints for audit diffing, suppression matching, baseline tracking, and evidence traceability |
| Agent intents | 32: FullAudit, FirewallCheck, NetworkCheck, ServiceCheck, PortCheck, SshCheck, FilePermissionCheck, FilesystemAuditCheck, KernelCheck, UserAccountCheck, LoggingAuditCheck, CronJobCheck, PackageVulnerabilityCheck, ContainerCheck, KubernetesCheck, ThreatIntelCheck, ExplainFinding, ShowChanges, ExplainCritical, FilterCategory, PrioritizeRemediation, FixFinding, ListSuppressed, SetBaseline, CheckDrift, ShowBaseline, RiskScore, StartRemediation, VerifyRemediation, ListRemediationSessions, ResumeRemediation, Help |
| CIS mapping coverage | 76 / 79 rules (96%): dual-layer CIS Controls v8 + CIS Ubuntu 24.04 LTS Benchmark. Threat intel rules (TI-001/002/003) intentionally have no CIS mappings. |
| CIS mapping fields | ControlId, ControlName, WhyItMatters, BenchmarkReference |
| Auto-fix policies | 3: Conservative (ReadOnly only), Standard (ReadOnly + ConfigChange), Aggressive (+ ServiceRestart). Destructive and Unknown are never auto-executed. |
| Command safety levels | 5: ReadOnly, ConfigChange, ServiceRestart, PackageInstall, Destructive, Unknown |
| Auto-fix exit codes | 0=success/nothing to fix, 1=error/invalid input, 2=unsafe commands skipped, 3=apply/rollback failure. Audit exit code 2 (critical findings) is never masked. |
| Compliance scorecard | Per-family Pass/Warn/Fail, overall rule-level percentage, trend over time (last 10 audits) |
| Compliance thresholds | Pass ≥90%, Warn ≥80%, Fail <80% (named constants on `ComplianceScorecard`) |
| Risk scorecard | Aggregate letter grade (A–F), numeric score (0–100), summary status, per-category breakdown ordered by total deduction |
| Risk scoring formula | `SeverityValue × 5 × AverageControlWeight` per finding; Info findings excluded |
| Risk grade thresholds | A ≥90, B ≥80, C ≥70, D ≥60, F <60 (named constants on `RiskScorecard`) |
| Target references | Rule IDs and category keywords extracted from explanation queries |
| Explanation templates | 12 embedded markdown files |
| Threat intel formats | STIX 2.1 bundles, MISP event JSON |
| Threat intel IOC types | IPv4, IPv6, Domain, URL, Port, FileHash (SHA-256/MD5/SHA-1) |
| Threat intel persistence | JSON in `~/.config/VulcansTrace/threat-intel.json` |
| UI integration | Collapsible Avalonia Security Agent chat panel with quick actions, grouped and filterable findings, rule coverage totals, selection-aware explanations, safety-labeled and structurally badged verification commands, timed suppressions, persistent selectable audit history diff with narrative summaries, privilege warnings, audit export, guarded remediation export, and interactive single-finding remediation cards with an impact preview panel, preconditions, backup/apply/rollback/verification commands and safety badges |
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
- **CIS Compliance Scorecard** — formal pass/fail/warn per control family, overall percentage score, and trend over time, readable in 10 seconds by managers and auditors; exported as HTML and Markdown in signed evidence bundles
- **Risk Scorecard** — aggregate letter grade (A–F) and numeric score (0–100) weighted by severity and CIS control importance, with per-category breakdown; available in agent chat and exported as HTML and Markdown in signed evidence bundles
- **Auto-Fix with Dry-Run** — batch remediation with `--auto-fix --dry-run` for safe preview before change, showing an impact preview per finding (expected impact, rollback path, verification command), policy-gated execution (Conservative/Standard/Aggressive), automatic rollback on failure, and clean exit codes that preserve critical-finding status
- **Remediation Session History Browser** — persisted sessions can be listed, resumed, and deleted through both the Avalonia UI expander and natural-language chat commands, ensuring no remediation workflow is lost between app restarts

---

## Key Evidence

- [SecurityAgent.cs](../../../../VulcansTrace.Linux.Agent/SecurityAgent.cs) — thin orchestration entry point
- [QueryParser.cs](../../../../VulcansTrace.Linux.Agent/Query/QueryParser.cs) — intent parsing
- [ScannerCoordinator.cs](../../../../VulcansTrace.Linux.Agent/Scanners/ScannerCoordinator.cs) — concurrent scanner execution and warning aggregation
- [RuleEvaluationService.cs](../../../../VulcansTrace.Linux.Agent/Rules/RuleEvaluationService.cs) — intent filtering, policy handling, contextual evaluation, crash handling, auto-pass, and severity overrides
- [FindingAssemblyService.cs](../../../../VulcansTrace.Linux.Agent/Reports/FindingAssemblyService.cs) — explanation lookup, finding creation, and suppression marking
- [AgentResultComposer.cs](../../../../VulcansTrace.Linux.Agent/Reports/AgentResultComposer.cs) — summary and capability report composition
- [AgentLogAnalysisService.cs](../../../../VulcansTrace.Linux.Agent/Reports/AgentLogAnalysisService.cs) — optional raw-log analysis bridge
- [AgentResultFinalizer.cs](../../../../VulcansTrace.Linux.Agent/Reports/AgentResultFinalizer.cs) — result construction, scorecard attachment, and audit-state update
- [AgentFollowUpService.cs](../../../../VulcansTrace.Linux.Agent/Reports/AgentFollowUpService.cs) — deterministic follow-up workflows
- [FindingExplanationService.cs](../../../../VulcansTrace.Linux.Agent/Reports/FindingExplanationService.cs) — selected-finding and referenced-rule explanation workflow
- [BaselineDriftService.cs](../../../../VulcansTrace.Linux.Agent/Baselines/BaselineDriftService.cs) — baseline save/show/drift workflow
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
- [LoggingAuditScanner.cs](../../../../VulcansTrace.Linux.Agent/Scanners/LoggingAuditScanner.cs) — logging service status, auditd rules, logrotate, and central forwarding collection
- [CronJobScanner.cs](../../../../VulcansTrace.Linux.Agent/Scanners/CronJobScanner.cs) — cron job entry collection from system and user crontabs
- [PackageVulnerabilityScanner.cs](../../../../VulcansTrace.Linux.Agent/Scanners/PackageVulnerabilityScanner.cs) — installed package enumeration, security update detection, and CVE enrichment
- [ContainerScanner.cs](../../../../VulcansTrace.Linux.Agent/Scanners/ContainerScanner.cs) — container runtime state collection, socket exposure/mount checks, and risky base-image hint detection (docker, crictl, ctr)
- [KubernetesScanner.cs](../../../../VulcansTrace.Linux.Agent/Scanners/KubernetesScanner.cs) — Kubernetes pod security posture collection via kubectl and the configured cluster context
- [FileHashScanner.cs](../../../../VulcansTrace.Linux.Agent/Scanners/FileHashScanner.cs) — SHA-256/MD5/SHA-1 hash collection for security-interesting files
- [StixParser.cs](../../../../VulcansTrace.Linux.Agent/ThreatIntel/StixParser.cs) — STIX 2.1 bundle parser
- [MispParser.cs](../../../../VulcansTrace.Linux.Agent/ThreatIntel/MispParser.cs) — MISP event JSON parser
- [InMemoryThreatIntelStore.cs](../../../../VulcansTrace.Linux.Agent/ThreatIntel/InMemoryThreatIntelStore.cs) — in-memory IOC store
- [JsonFileThreatIntelStore.cs](../../../../VulcansTrace.Linux.Agent/ThreatIntel/JsonFileThreatIntelStore.cs) — persisted JSON IOC store
- [ThreatIntelDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/ThreatIntelDetector.cs) — firewall log correlation against imported IOCs
- [FirewallRules.cs](../../../../VulcansTrace.Linux.Agent/Rules/SecurityRules/FirewallRules.cs) — firewall posture rules
- [PortRules.cs](../../../../VulcansTrace.Linux.Agent/Rules/SecurityRules/PortRules.cs) — exposed-port rules
- [ServiceRules.cs](../../../../VulcansTrace.Linux.Agent/Rules/SecurityRules/ServiceRules.cs) — service posture rules
- [NetworkRules.cs](../../../../VulcansTrace.Linux.Agent/Rules/SecurityRules/NetworkRules.cs) — routing and connection rules
- [FilePermissionRules.cs](../../../../VulcansTrace.Linux.Agent/Rules/SecurityRules/FilePermissionRules.cs) — file permission posture rules
- [FilesystemAuditRules.cs](../../../../VulcansTrace.Linux.Agent/Rules/SecurityRules/FilesystemAuditRules.cs) — filesystem audit posture rules
- [LoggingAuditRules.cs](../../../../VulcansTrace.Linux.Agent/Rules/SecurityRules/LoggingAuditRules.cs) — logging and audit posture rules
- [CronJobRules.cs](../../../../VulcansTrace.Linux.Agent/Rules/SecurityRules/CronJobRules.cs) — cron job posture rules
- [PackageVulnerabilityRules.cs](../../../../VulcansTrace.Linux.Agent/Rules/SecurityRules/PackageVulnerabilityRules.cs) — package vulnerability posture rules
- [DefaultRulePolicyProvider.cs](../../../../VulcansTrace.Linux.Agent/Rules/DefaultRulePolicyProvider.cs) — built-in role defaults and local override merge behavior
- [JsonRulePolicyStore.cs](../../../../VulcansTrace.Linux.Agent/Rules/JsonRulePolicyStore.cs) — persisted rule policy store
- [Finding.cs](../../../../VulcansTrace.Linux.Core/Finding.cs) — stable finding identity and fingerprints
- [AuditDiffCalculator.cs](../../../../VulcansTrace.Linux.Agent/Reports/AuditDiffCalculator.cs) — fingerprint-aware audit comparison
- [BaselineEntry.cs](../../../../VulcansTrace.Linux.Agent/Baselines/BaselineEntry.cs) — baseline snapshot with original findings
- [IBaselineStore.cs](../../../../VulcansTrace.Linux.Agent/Baselines/IBaselineStore.cs) — baseline storage contract
- [JsonFileBaselineStore.cs](../../../../VulcansTrace.Linux.Agent/Baselines/JsonFileBaselineStore.cs) — persisted baseline store
- [SuppressionEntry.cs](../../../../VulcansTrace.Linux.Agent/Rules/SuppressionEntry.cs) — fingerprint-scoped accepted-risk entries
- [AgentViewModel.cs](../../../../VulcansTrace.Linux.Avalonia/ViewModels/AgentViewModel.cs) — UI command flow
- [AgentMessageViewModel.cs](../../../../VulcansTrace.Linux.Avalonia/ViewModels/AgentMessageViewModel.cs) — chat message and remediation-card state
- [AgentOperationRunner.cs](../../../../VulcansTrace.Linux.Avalonia/ViewModels/AgentOperationRunner.cs) — async operation lifecycle, cancellation, busy state, and error messaging
- [AgentResultPresenter.cs](../../../../VulcansTrace.Linux.Avalonia/ViewModels/AgentResultPresenter.cs) — chat rendering, grouped findings, filters, warnings, and remediation cards
- [AgentHistoryCoordinator.cs](../../../../VulcansTrace.Linux.Avalonia/ViewModels/AgentHistoryCoordinator.cs) — persisted audit history refresh, comparison, and exported-state tracking
- [ComplianceScorecardBuilder.cs](../../../../VulcansTrace.Linux.Agent/Reports/ComplianceScorecardBuilder.cs) — compliance scorecard computation
- [ComplianceScorecardViewModel.cs](../../../../VulcansTrace.Linux.Avalonia/ViewModels/ComplianceScorecardViewModel.cs) — compliance tab binding
- [RiskScorecardBuilder.cs](../../../../VulcansTrace.Linux.Agent/Reports/RiskScorecardBuilder.cs) — aggregate risk score computation
- [RiskScorecardViewModel.cs](../../../../VulcansTrace.Linux.Avalonia/ViewModels/RiskScorecardViewModel.cs) — risk score tab binding
- [GuidedRemediationService.cs](../../../../VulcansTrace.Linux.Agent/Reports/GuidedRemediationService.cs) — remediation session lifecycle, blocked-state handling, verification, and before/after diffing
- [RemediationSession.cs](../../../../VulcansTrace.Linux.Agent/Sessions/RemediationSession.cs) — remediation session model, step state, snapshots, and verification result
- [JsonFileSessionStore.cs](../../../../VulcansTrace.Linux.Agent/Sessions/JsonFileSessionStore.cs) — persisted remediation session store
- [InMemorySessionStore.cs](../../../../VulcansTrace.Linux.Agent/Sessions/InMemorySessionStore.cs) — session fallback store
- [RemediationPlanBuilder.cs](../../../../VulcansTrace.Linux.Agent/Remediation/RemediationPlanBuilder.cs) — builds per-rule remediation plans from explanations
- [RemediationExecutor.cs](../../../../VulcansTrace.Linux.Agent/Remediation/RemediationExecutor.cs) — orchestrates backup, apply, rollback, and verify with policy enforcement
- [AutoFixPolicy.cs](../../../../VulcansTrace.Linux.Agent/Remediation/AutoFixPolicy.cs) — configurable command-safety permission levels
- [ProcessRunner.cs](../../../../VulcansTrace.Linux.Agent/Remediation/ProcessRunner.cs) — safe shell command execution with stdin feeding and exception resilience
- [IProcessRunner.cs](../../../../VulcansTrace.Linux.Agent/Remediation/IProcessRunner.cs) — execution contract
- [RemediationConsoleFormatter.cs](../../../../VulcansTrace.Linux.Agent/Reports/RemediationConsoleFormatter.cs) — `--dry-run` and `--auto-fix` console output
- [RemediationPlanValidator.cs](../../../../VulcansTrace.Linux.Agent/Reports/RemediationPlanValidator.cs) — validation before execution
- [SecurityAgentTests.cs](../../../../VulcansTrace.Linux.Tests/Agent/SecurityAgentTests.cs) — orchestration tests
- [ComplianceScorecardBuilderTests.cs](../../../../VulcansTrace.Linux.Tests/Agent/ComplianceScorecardBuilderTests.cs) — compliance scorecard computation tests
- [RiskScorecardBuilderTests.cs](../../../../VulcansTrace.Linux.Tests/Agent/RiskScorecardBuilderTests.cs) — risk scorecard computation tests
- [ScannerParserFixtureTests.cs](../../../../VulcansTrace.Linux.Tests/Agent/ScannerParserFixtureTests.cs) — realistic command-output parser fixtures

---

## Current Status

This is a v1 local security assistant. It can scan, evaluate, report data-source capability status, tune selected rules by machine role and local JSON policy, explain selected or referenced findings, answer deterministic follow-up questions (changes since last audit, critical explanations, category filtering, prioritized remediation, interactive single-finding remediation, suppressed listing) without re-running scans, group and filter results in the UI, surface privilege-limited scans, preserve and expire fingerprint-scoped accepted-risk suppressions, keep recently expired suppressions reviewable for 30 days, compare selected audits with fingerprint matching and a deterministic change narrative, snapshot known-good configuration baselines per intent, detect drift against those baselines with new and worsened findings surfaced as actionable results, display baselines with original finding details preserved, export guarded remediation previews with explicit rollback requirements for risky commands, guide users through step-by-step interactive remediation for individual findings with a compact impact preview, safety-classified commands and rollback visibility, execute batch auto-fix with policy-gated permissions, automatic rollback on failure, dry-run preview, and clean exit codes that preserve critical-finding status, and export agent audits with capability and active suppression notes through the shared evidence workflow. It is not an LLM-backed conversational agent. The next high-value improvements are a UI role selector, broader distro-specific parser fixtures, a "Fix Selected" quick-action button, and reminder surfaces for upcoming suppression reviews.
