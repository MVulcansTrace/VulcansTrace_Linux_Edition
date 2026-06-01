# Architecture

VulcansTrace Linux Edition is structured as layered projects that keep parsing, detection, UI, and evidence packaging isolated. The result is a local-only analysis pipeline that can be reused by UI and CLI tools.

## System Overview

- `VulcansTrace.Linux.Core`: domain models and log parsing (UnifiedEvent, LogNormalizer).
- `VulcansTrace.Linux.Engine`: detectors, profiles, and analysis orchestration.
- `VulcansTrace.Linux.Evidence`: evidence bundle creation and report formatting.
- `VulcansTrace.Linux.Agent`: local Security Agent, live host scanners, posture rules, role-aware policy, explanations, and report adaptation.
- `VulcansTrace.Linux.Avalonia`: Avalonia UI and composition root.
- `VulcansTrace.Linux.Cli`: headless CLI for audits, schedule management, and system cron integration.
- `VulcansTrace.Linux.Tests`: unit and integration tests.
- `VulcansTrace.Linux.Performance`: performance benchmarks and metrics.
- `VulcansTrace.Linux.PerformanceConsole`: console runner for performance tests.
- `tools/TestAnalysis`: sample CLI analysis runner (not part of the solution file).

## Data Flow

1. Raw firewall log text is provided by the UI or a tool.
2. `LogNormalizer` detects iptables vs nftables and produces `UnifiedEvent` entries.
3. `SentryAnalyzer` runs three detector layers:
   - Baseline detectors (ported from Windows logic).
   - Linux Deep Inspection detectors (Linux-specific signals).
   - Advanced threat detectors (C2 channels, privilege escalation).
4. `RiskEscalator` increases severity when correlated signals are present.
5. Overlapping Beaconing and C2Channel findings on the same source-destination tuple are deduplicated (C2Channel absorbs the Beaconing details).
6. Findings are filtered by the profile's minimum severity (`MinSeverityToShow`) and per-category cap (`MaxFindingsPerDetector`).
7. `AnalysisResult` is returned with findings, warnings, parse errors, and time range metadata.
8. The UI renders findings, and `EvidenceBuilder` optionally creates a signed bundle.

The Security Agent provides a parallel local posture path:

1. A natural-language query is parsed into an `AgentIntent`.
2. Agent scanners collect firewall, port, service, SSH daemon configuration, file permissions, filesystem audit findings (world-writable files, SUID/SGID binaries, unowned files, sticky-bit checks, /tmp mount options), kernel and system hardening parameters, user accounts, shadow entries, password aging, PAM configuration, logging and audit configuration (rsyslog, journald, auditd rules, logrotate, central forwarding), cron job entries and script permissions, interface, route, and connection state from local Linux commands, plus data-source capability status for those commands.
3. Role-aware rule policy resolves built-in defaults and local JSON overrides.
4. Agent rules evaluate the collected `ScanData`, including contextual parameters when supported.
5. Failed posture checks become `Finding` records with stable fingerprints, markdown-backed explanations, and **dual-layer CIS Benchmark mappings** (CIS Controls v8 + CIS Ubuntu 24.04 LTS technical controls).
6. Optional pasted firewall logs can be analyzed through `SentryAnalyzer`.
7. `ComplianceScorecardBuilder` computes a formal CIS compliance scorecard from rule results: per-family pass/fail/warn scores, an overall rule-level percentage, and a trend over time using `IAuditHistoryStore`.
8. `AuditDiffCalculator` compares audit snapshots for history diffs and baseline drift detection.
9. `IBaselineStore` persists user-designated known-good baselines; `JsonFileBaselineStore` writes to `~/.config/VulcansTrace/baselines.json`.
10. `AgentReportGenerator` can adapt agent results back into `AnalysisResult`.

The **Auto-Fix pipeline** extends the Security Agent to headless batch remediation:

1. `RemediationPlanBuilder` constructs a `RemediationPlan` from agent `Finding` records by parsing explanation templates into structured sections.
2. `CommandSafetyClassifier` analyzes each extracted command and labels it `ReadOnly`, `ConfigChange`, `ServiceRestart`, `PackageInstall`, `Destructive`, or `Unknown`.
3. `AutoFixPolicy` defines which safety classifications are permitted for automatic execution (configurable via `--allow-restart` and `--allow-packages`).
4. `RemediationPlanValidator` blocks sections where risky or unclassified commands lack explicit rollback guidance.
5. `RemediationExecutor` orchestrates the execution: backup commands first, then apply commands, then verification commands. If an apply command fails, rollback commands are executed automatically. Cancellation is checked before every command.
6. `ProcessRunner` executes shell commands via bash stdin (not `-c` argument wrapping) to avoid shell escaping vulnerabilities, with configurable timeout and cancellation support.
7. `RemediationConsoleFormatter` renders dry-run previews and execution results for CLI output.

The Scheduling layer provides recurring audit automation:

1. `AuditSchedule` records define intent, cron expression, machine role, notification channel, and enabled state.
2. `IScheduleStore` persists schedules (`JsonFileScheduleStore` → `~/.config/VulcansTrace/schedules.json`); `InMemoryScheduleStore` provides a fallback.
3. `CrontabManager` reads/writes the system user crontab, using a unique marker prefix to identify VulcansTrace entries.
4. `CronExpressionValidator` validates 5-field cron syntax before persistence or crontab installation.
5. Scheduled audits run through the CLI (`vulcanstrace schedule run --id <id>`), which compares critical findings against the previous `AuditHistoryEntry` via fingerprint diffing and only notifies on new criticals.
6. `IAuditHistoryStore` persists lightweight audit snapshots (`JsonFileAuditHistoryStore` → `~/.config/VulcansTrace/audithistory.json`) for diff comparison and compliance trend calculation.

Notification services are pluggable:

- `INotificationService` abstraction with `NotifyCriticalFindingsAsync`.
- `NotifySendNotificationService` shells out to `notify-send` for desktop alerts.
- `EmailNotificationService` sends SMTP email with TLS and credential support.
- `WebhookNotificationService` POSTs JSON payloads with retry logic for transient failures.
- All notification services catch exceptions and log to `stderr` so notification failures do not crash audits.

## Key Domain Types

- `UnifiedEvent`: normalized schema for firewall logs, including Linux-specific fields.
- `AnalysisProfile`: intensity-tuned thresholds for each detector.
- `Finding`: immutable detector output with severity, time range, and a stable fingerprint for tracking the same issue across audits.
- `AnalysisResult`: complete analysis output with entries, findings, warnings, and optional agent data-source capability context.
- `ComplianceScorecard`: formal CIS compliance summary with per-family scores, overall percentage, pass/warn/fail status, and trend points.

## Detection Layers

Baseline detectors:
- PortScan, Flood, LateralMovement, Beaconing, PolicyViolation, Novelty.

Linux Deep Inspection detectors:
- FlagAnomaly, MacSpoofing, KernelModule, InterfaceHopping, UnusualPacketSize.

Advanced threat detectors:
- C2Channel, PrivilegeEscalation.

Risk escalation correlations include (when both findings occur within a correlated 24-hour window):
- Beaconing + LateralMovement -> Critical.
- FlagAnomaly + PortScan -> Critical.
- MacSpoofing + InterfaceHopping -> Critical.

## Logging

Runtime logging is abstracted behind `ILogSink`. The UI uses `DiagnosticsLogSink` to emit to `System.Diagnostics.Trace`, while parsers and engine default to `NullLogSink` if no sink is provided.
