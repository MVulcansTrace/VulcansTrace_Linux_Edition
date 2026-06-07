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
- **Live host scanning** — collects firewall, port, service, SSH daemon configuration, file permissions, filesystem audit findings, kernel and system hardening parameters, user accounts, shadow entries, password aging, PAM configuration, interface, route, connection state, logging service status, auditd rules, logrotate, central forwarding targets, cron job entries, installed package inventory, pending security updates, unattended-upgrades configuration, container runtime state (Docker/containerd availability, running containers, privileged mode, image tags, socket exposure/mounts, risky base-image hints, namespace isolation), Kubernetes pod security posture (privileged pods, host namespace sharing, root containers, missing security contexts), file hashes of security-interesting files (SUID/SGID binaries, world-writable files, unowned files, cron scripts), and YARA rule matches for binaries and scripts via `libyara` through local Linux commands and the configured kubectl context
- **Data-source capability reporting** — records whether scanner inputs are available, unavailable, permission-limited, or intentionally not checked
- **Rule-based posture checks** — evaluates firewall, port, service, SSH, file permission, filesystem audit, kernel hardening, network, cron job, package vulnerability, container, Kubernetes, threat intel, and YARA rules without external AI dependencies
- **Role-aware local policy** — tunes selected rules for Workstation, Server, LabBox, Router, and DevMachine profiles with JSON overrides; the Avalonia UI includes a role dropdown for hot-swapping without code changes
- **Human-readable explanations** — turns failed rules into markdown-backed explanations with template variables
- **Stable finding fingerprints** — tracks the same posture issue across audit history, suppression matching, and evidence exports without depending on volatile wording or timestamps
- **Structured explanation sections** — separates what was found, why it matters, how to verify, preconditions, backup commands, suggested next action, rollback commands, confidence, and caveats
- **Copyable verification commands** — exposes only verification-section commands for clipboard copy and labels each with command safety and structural badges
- **Log-analysis bridge** — can include pasted firewall logs through the existing `SentryAnalyzer`
- **Evidence compatibility** — converts agent output back into `AnalysisResult` through `AgentReportGenerator`, preserves rule IDs, fingerprints, capability reports, and active suppression notes in evidence exports
- **Deterministic follow-up questions** — operates on the last audit result without re-running scans: changes since last audit, critical/high explanations, category filtering, prioritized remediation, interactive single-finding remediation with pre-flight impact simulation, suppressed listing, and batch headless auto-fix with dry-run preview and policy-gated execution
- **Automated Incident Response Playbooks** — when `TraceMapCorrelator` detects a Beaconing → LateralMovement → PrivilegeEscalation triplet, the agent auto-generates active countermeasures (iptables DROP + auditd monitor) against the attacker's C2 IP with dry-run preview, IP validation, deduplication, and explicit confirmation before live deployment
- **Configuration baseline & drift detection** — saves a "known good" baseline per intent, compares live audits against it, and reports new and worsened findings as drift with narrative summaries; preserves original finding details for lossless baseline display
- **Timed suppressions** — supports fingerprint-scoped 7-day, 30-day, 90-day, and permanent accepted-risk suppressions; expired suppressions stop applying immediately but remain reviewable for 30 days before pruning
- **Remediation Session History Browser** — lists all persisted sessions with ID, status, rule ID, and creation time; supports resuming into the chat panel and deleting from the store, plus natural-language chat commands (`list my sessions`, `show sessions`, `resume session <id>`)
- **Avalonia chat panel** — exposes chat, quick actions, grouped and filterable findings, selected-finding explanations, privilege warnings, rule coverage totals, persistent selectable audit history diff with narrative summaries, baseline set/drift/show actions, suppression review actions, cancellation, audit export, guarded remediation preview export, guided session timelines with success-only export tracking, and a Remediation Sessions expander for session resume/delete
- **Dual-layer CIS Benchmark mapping** — every rule maps to both CIS Controls v8 (organizational) and CIS Ubuntu 24.04 LTS Benchmark (technical) for audit-ready compliance traceability
- **CIS Compliance Scorecard** — formal pass/fail/warn per control family, overall percentage score, and trend over time, readable in 10 seconds by managers and auditors
- **Risk Scorecard** — aggregate letter grade (A–F) and numeric score (0–100) derived from all risk-relevant findings, weighted by severity and CIS control importance. Surfaces top risk categories by deduction in the Avalonia UI, agent chat, and evidence exports.
- **Deterministic tests** — verifies intent parsing, scanner parser fixtures, rule behavior, explanations, reports, baseline store persistence, drift detection, agent orchestration, compliance scorecard computation, risk scorecard computation, and CIS mapping flow-through across all execution paths

## Implementation Evidence

- [SecurityAgent.cs](../../../VulcansTrace.Linux.Agent/SecurityAgent.cs) — thin agent orchestrator that delegates scanning, rule evaluation, finding assembly, follow-ups, baseline/drift, explanation, log-analysis, and result finalization
- [IAgent.cs](../../../VulcansTrace.Linux.Agent/IAgent.cs) — public agent interface
- [QueryParser.cs](../../../VulcansTrace.Linux.Agent/Query/QueryParser.cs) — keyword-scored intent parser
- [ScannerCoordinator.cs](../../../VulcansTrace.Linux.Agent/Scanners/ScannerCoordinator.cs) — concurrent scanner execution and warning aggregation
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
- [LoggingAuditScanner.cs](../../../VulcansTrace.Linux.Agent/Scanners/LoggingAuditScanner.cs) — logging service status, auditd rules, logrotate, and central forwarding collection
- [CronJobScanner.cs](../../../VulcansTrace.Linux.Agent/Scanners/CronJobScanner.cs) — cron job entry collection from system and user crontabs
- [PackageVulnerabilityScanner.cs](../../../VulcansTrace.Linux.Agent/Scanners/PackageVulnerabilityScanner.cs) — installed package enumeration, security update detection, and CVE enrichment
- [ContainerScanner.cs](../../../VulcansTrace.Linux.Agent/Scanners/ContainerScanner.cs) — container runtime state collection, socket exposure/mount checks, and risky base-image hint detection (docker, crictl, ctr)
- [KubernetesScanner.cs](../../../VulcansTrace.Linux.Agent/Scanners/KubernetesScanner.cs) — Kubernetes pod security posture collection via kubectl and the configured cluster context
- [FileHashScanner.cs](../../../VulcansTrace.Linux.Agent/Scanners/FileHashScanner.cs) — SHA-256/MD5/SHA-1 hash collection for security-interesting files
- [YaraScanner.cs](../../../VulcansTrace.Linux.Agent/Scanners/Yara/YaraScanner.cs) — YARA rule scanning for SUID/SGID binaries, running process executables, and cron scripts
- [LibyaraEngine.cs](../../../VulcansTrace.Linux.Agent/Scanners/Yara/LibyaraEngine.cs) — thin P/Invoke wrapper around `libyara`
- [bundled.yar](../../../VulcansTrace.Linux.Agent/Scanners/Yara/Rules/bundled.yar) — embedded starter YARA rules
- [SecurityRules](../../../VulcansTrace.Linux.Agent/Rules/SecurityRules) — firewall, network, service, port, SSH, file permission, filesystem audit, kernel hardening, user account, logging, cron job, package vulnerability, container, Kubernetes, threat intel, and YARA checks
- [ThreatIntel](../../../VulcansTrace.Linux.Agent/ThreatIntel) — STIX 2.1 and MISP JSON parsers, IOC store implementations, and import result models
- [RuleEvaluationService.cs](../../../VulcansTrace.Linux.Agent/Rules/RuleEvaluationService.cs) — intent filtering, contextual rule evaluation, local policy handling, crash handling, auto-pass, and severity overrides
- [FindingAssemblyService.cs](../../../VulcansTrace.Linux.Agent/Reports/FindingAssemblyService.cs) — explanation lookup, finding creation, suppression checks, and active finding history entries
- [AgentResultComposer.cs](../../../VulcansTrace.Linux.Agent/Reports/AgentResultComposer.cs) — audit summary text and deterministic capability report formatting
- [AgentLogAnalysisService.cs](../../../VulcansTrace.Linux.Agent/Reports/AgentLogAnalysisService.cs) — optional pasted-log analysis bridge to `SentryAnalyzer`
- [AgentResultFinalizer.cs](../../../VulcansTrace.Linux.Agent/Reports/AgentResultFinalizer.cs) — final `AgentResult` construction, scorecard attachment, and audit-state updates
- [AgentAuditState.cs](../../../VulcansTrace.Linux.Agent/Reports/AgentAuditState.cs) — previous audit result, previous audit intent, and finding lookup state for follow-up questions
- [AgentFollowUpService.cs](../../../VulcansTrace.Linux.Agent/Reports/AgentFollowUpService.cs) — deterministic follow-up question handlers
- [FindingExplanationService.cs](../../../VulcansTrace.Linux.Agent/Reports/FindingExplanationService.cs) — selected-finding and referenced-rule explanation flow
- [SingleRuleExplanationService.cs](../../../VulcansTrace.Linux.Agent/Reports/SingleRuleExplanationService.cs) — explain-by-rule path for targeted single-rule checks
- [Finding.cs](../../../VulcansTrace.Linux.Core/Finding.cs) — stable finding fingerprints
- [AuditDiffCalculator.cs](../../../VulcansTrace.Linux.Agent/Reports/AuditDiffCalculator.cs) — fingerprint-aware audit diffing
- [BaselineDriftService.cs](../../../VulcansTrace.Linux.Agent/Baselines/BaselineDriftService.cs) — baseline save, baseline display, and drift comparison workflow
- [BaselineEntry.cs](../../../VulcansTrace.Linux.Agent/Baselines/BaselineEntry.cs) — baseline snapshot with original findings
- [IBaselineStore.cs](../../../VulcansTrace.Linux.Agent/Baselines/IBaselineStore.cs) — baseline storage contract
- [JsonFileBaselineStore.cs](../../../VulcansTrace.Linux.Agent/Baselines/JsonFileBaselineStore.cs) — persisted baseline store
- [DefaultRulePolicyProvider.cs](../../../VulcansTrace.Linux.Agent/Rules/DefaultRulePolicyProvider.cs) — built-in role defaults and user-policy merge behavior
- [JsonRulePolicyStore.cs](../../../VulcansTrace.Linux.Agent/Rules/JsonRulePolicyStore.cs) — local JSON policy persistence
- [ExplanationProvider.cs](../../../VulcansTrace.Linux.Agent/Explanations/ExplanationProvider.cs) — embedded markdown explanation loading
- [AgentReportGenerator.cs](../../../VulcansTrace.Linux.Agent/Reports/AgentReportGenerator.cs) — agent-to-analysis result adapter
- [AgentViewModel.cs](../../../VulcansTrace.Linux.Avalonia/ViewModels/AgentViewModel.cs) — chat panel ViewModel
- [AgentMessageViewModel.cs](../../../VulcansTrace.Linux.Avalonia/ViewModels/AgentMessageViewModel.cs) — chat message state, remediation-card state, and copy command behavior
- [AgentOperationRunner.cs](../../../VulcansTrace.Linux.Avalonia/ViewModels/AgentOperationRunner.cs) — async operation lifecycle, cancellation, busy state, and error messaging
- [AgentResultPresenter.cs](../../../VulcansTrace.Linux.Avalonia/ViewModels/AgentResultPresenter.cs) — chat rendering, grouped findings, filters, warnings, and remediation cards
- [AgentHistoryCoordinator.cs](../../../VulcansTrace.Linux.Avalonia/ViewModels/AgentHistoryCoordinator.cs) — persisted audit history refresh, comparisons, exported-state tracking, and persistence warnings
- [AgentView.axaml](../../../VulcansTrace.Linux.Avalonia/AgentView.axaml) — chat panel UI including Remediation Sessions expander
- [IAgent.cs](../../../VulcansTrace.Linux.Agent/IAgent.cs) — public agent interface with session list/load/delete
- [GuidedRemediationService.cs](../../../VulcansTrace.Linux.Agent/Reports/GuidedRemediationService.cs) — remediation session lifecycle, blocked-state handling, verification, before/after diffing, and session store operations
- [RemediationSession.cs](../../../VulcansTrace.Linux.Agent/Sessions/RemediationSession.cs) — remediation session model, step state, snapshots, and verification result
- [JsonFileSessionStore.cs](../../../VulcansTrace.Linux.Agent/Sessions/JsonFileSessionStore.cs) — persisted remediation session store
- [InMemorySessionStore.cs](../../../VulcansTrace.Linux.Agent/Sessions/InMemorySessionStore.cs) — session fallback store
- [RemediationPlanBuilder.cs](../../../VulcansTrace.Linux.Agent/Remediation/RemediationPlanBuilder.cs) — builds per-rule remediation plans from explanations
- [RemediationExecutor.cs](../../../VulcansTrace.Linux.Agent/Remediation/RemediationExecutor.cs) — orchestrates backup, apply, rollback, and verify with policy enforcement
- [AutoFixPolicy.cs](../../../VulcansTrace.Linux.Agent/Remediation/AutoFixPolicy.cs) — configurable command-safety permission levels
- [ProcessRunner.cs](../../../VulcansTrace.Linux.Agent/Remediation/ProcessRunner.cs) — safe shell command execution with stdin feeding and exception resilience
- [RemediationConsoleFormatter.cs](../../../VulcansTrace.Linux.Agent/Reports/RemediationConsoleFormatter.cs) — `--dry-run` and `--auto-fix` console output
- [RemediationPlanValidator.cs](../../../VulcansTrace.Linux.Agent/Reports/RemediationPlanValidator.cs) — validation before execution
- [RiskScorecardBuilder.cs](../../../VulcansTrace.Linux.Agent/Reports/RiskScorecardBuilder.cs) — aggregate risk score computation from findings
- [RiskScorecardViewModel.cs](../../../VulcansTrace.Linux.Avalonia/ViewModels/RiskScorecardViewModel.cs) — risk score tab binding and grade-color mapping
- [Agent tests](../../../VulcansTrace.Linux.Tests/Agent) — query, rule, explanation, report, risk scorecard, and orchestration coverage
- [Evidence formatter tests](../../../VulcansTrace.Linux.Tests/Evidence) — rule ID preservation through CSV, JSON, Markdown, HTML, and STIX exports
