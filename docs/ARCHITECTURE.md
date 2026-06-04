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

## Live Stream Components

- `IEventSource` — abstraction for real-time event producers (packet capture, NFLOG, synthetic).
- `PacketCaptureEventSource` — `AF_PACKET` + classic BPF socket filter.
- `NflogEventSource` — `AF_NETLINK` NFLOG structured event reader.
- `SyntheticEventSource` — deterministic traffic generator for zero-privilege testing.
- `LiveStreamWindow` — thread-safe rolling buffer with time/count eviction.
- `LiveStreamAnalyzer` — orchestrates source → channel → window → analysis → dedup.
- `LiveStreamViewModel` — Avalonia UI logic for source selection, start/stop, and metrics.
- `LiveAnalysisResult` — delta findings and window metrics for UI display.

## Data Flow

1. Raw firewall log text is provided by the UI or a tool.
2. `LogNormalizer` detects iptables vs nftables and produces `UnifiedEvent` entries.
3. `SentryAnalyzer` runs three detector layers:
   - Baseline detectors (ported from Windows logic).
   - Linux Deep Inspection detectors (Linux-specific signals).
   - Advanced threat detectors (C2 channels, privilege escalation).
4. `RiskEscalator` increases severity when correlated signals are present.
5. `TraceMapCorrelator` discovers directed correlation edges between findings: escalation pairs (Beaconing→LateralMovement, FlagAnomaly→PortScan, MacSpoofing→InterfaceHopping), temporal sequences on the same host, and same-host cross-category links. Produces `TraceMapResult` containing the original findings plus `CorrelationEdge` records with confidence levels (High, Medium, Low) derived from time gap.
6. Overlapping Beaconing and C2Channel findings on the same source-destination tuple are deduplicated (C2Channel absorbs the Beaconing details).
7. Findings are filtered by the profile's minimum severity (`MinSeverityToShow`) and per-category cap (`MaxFindingsPerDetector`).
8. `AnalysisResult` is returned with findings, warnings, parse errors, and time range metadata.
9. The UI renders findings (including timeline and Trace Map visualization), and `EvidenceBuilder` optionally creates a signed bundle.

The **Live Stream** provides a parallel real-time analysis path:

1. `IEventSource` reads live events from `AF_PACKET` + classic BPF, `AF_NETLINK` NFLOG, or a synthetic generator.
2. `LiveStreamWindow` buffers events with dual eviction: 60-second time window and 10 000 event count cap.
3. A dedicated `SentryAnalyzer` instance runs on the window every 5 seconds or 500 events.
4. Completed `LiveAnalysisResult` records flow through a bounded `DropOldest` channel so stale UI updates do not stall analysis.
5. Findings are deduplicated by fingerprint (5-minute TTL) and stored in `LiveFindings` with FIFO eviction at 1 000 entries.
6. `LiveResultReceived` surfaces new findings to the UI, which adds them to the shared findings grid.
7. `StopAsync()` signals cancellation, closes the native socket (unblocking `recv()`), and awaits clean pipeline shutdown.

The Security Agent provides a parallel local posture path:

1. A natural-language query is parsed into an `AgentIntent`.
2. `ScannerCoordinator` runs agent scanners and builds a `ScanData` snapshot containing firewall, port, service, SSH daemon configuration, file permissions, filesystem audit findings (world-writable files, SUID/SGID binaries, unowned files, sticky-bit checks, /tmp mount options), kernel and system hardening parameters, user accounts, shadow entries, password aging, PAM configuration (password-stack and auth-stack configs, `pwquality.conf`, `faillock.conf`), logging and audit configuration (rsyslog, journald, auditd rules, logrotate, central forwarding), cron job entries and script permissions, installed package inventory and pending security updates (via dpkg, apt, and optionally debsecan for CVE enrichment), unattended-upgrades configuration, interface, route, connection state, and data-source capability status for local Linux commands.
3. `RuleEvaluationService` filters rules by intent, resolves role-aware policy from built-in defaults and local JSON overrides, invokes contextual rules when supported, converts rule crashes into explicit results, and applies auto-pass or severity override policy.
4. `FindingAssemblyService` converts failed posture checks into `Finding` records with stable fingerprints, markdown-backed explanations, suppression status, and **dual-layer CIS Benchmark mappings** (CIS Controls v8 + CIS Ubuntu 24.04 LTS technical controls).
5. `AgentLogAnalysisService` optionally analyzes pasted firewall logs through `SentryAnalyzer`.
6. `AgentResultComposer` builds user-facing summaries and deterministic data-source capability reports.
7. `AgentResultFinalizer` attaches `ComplianceScorecardBuilder` and `RiskScorecardBuilder` output, builds the final `AgentResult`, and updates `AgentAuditState` for follow-up questions.
8. `AgentFollowUpService`, `FindingExplanationService`, and `BaselineDriftService` answer deterministic follow-up questions, selected-finding explanations, baseline save/show, and drift comparison without making `SecurityAgent` own those workflows directly.
9. `AuditDiffCalculator` compares audit snapshots for history diffs and baseline drift detection.
10. `IBaselineStore` persists user-designated known-good baselines; `JsonFileBaselineStore` writes to `~/.config/VulcansTrace/baselines.json`.
11. `AgentReportGenerator` can adapt agent results back into `AnalysisResult`.
- `RemediationMarkdownFormatter` renders exported session reports with a `## Notes` section that groups session notes and step notes (by rule ID), showing timestamps, text, and extracted evidence links. Remediation plan exports include an `## Impact Preview` block per section showing expected impact, rollback path, and verification command.

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
- `TraceMapResult`: container for findings and their directed correlation edges (`CorrelationEdge`), produced by `TraceMapCorrelator`.
- `CorrelationEdge`: directed edge between two findings (`FromFindingId`, `ToFindingId`, `CorrelationType`, `Narrative`, `CorrelationConfidence`).
- `CorrelationType`: `EscalatesTo`, `SameHost`, or `TemporalSequence`.
- `CorrelationConfidence`: `Low`, `Medium`, or `High`, derived from time gap between findings.
- `ComplianceScorecard`: formal CIS compliance summary with per-family scores, overall percentage, pass/warn/fail status, and trend points.
- `RiskScorecard`: aggregate risk summary with letter grade (A–F), numeric score (0–100), summary status, and per-category risk breakdown weighted by severity and CIS control importance.
- `LiveAnalysisResult`: real-time analysis output containing delta findings (new since last run), window metrics, and source status.
- `LiveWindowMetrics`: live stream statistics (event rate, window size, analysis run count).

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

## Guided Remediation Sessions

The guided remediation layer adds session-aware, manual-first remediation with before/after verification on top of the existing Auto-Fix pipeline.

### Service Boundaries

- `GuidedRemediationService` — owns session lifecycle, plan building, step tracking, verification, before/after diffing, and session store operations (`ListSessionsAsync`, `LoadSessionAsync`, `DeleteSessionAsync`). Created by `SecurityAgent` and receives `RemediationPlanBuilder` via constructor injection (not inline creation).
- `AgentFollowUpService` — handles non-remediation follow-up queries only (`ShowChanges`, `ExplainCritical`, `FilterCategory`, `ListSuppressed`, `RiskScore`). Delegates `PrioritizeRemediation` and `FixFinding` intents to `GuidedRemediationService`.
- `RemediationPlanBuilder` — plan generation from findings (existing). Always injected, never created inline.
- `RemediationPlanValidator` — safety validation (existing).
- `RemediationExecutor` — command execution (existing, CLI path only).

### Session Model

- `RemediationSession` composes the existing `RemediationPlan` rather than duplicating it.
- `RemediationSessionStatus` tracks session lifecycle: `Active`, `Blocked`, `Completed`, `Verified`.
- `RemediationStepState` tracks per-section completion: `Pending`, `InProgress`, `Completed`, `Skipped`, `Blocked`, `Failed`.
- `AuditSnapshot` captures findings at session creation and after verification for before/after comparison.
- `RemediationSessionEvent` records immutable timeline events: `Created`, `StepMarkedPending`, `StepMarkedInProgress`, `StepMarkedCompleted`, `StepMarkedSkipped`, `StepMarkedFailed`, `StepBlocked`, `VerificationStarted`, `VerificationCompleted`, `VerificationBlocked`, `VerificationFailed`, `Exported`, `SessionResumed`, `SessionNoteAdded`, `StepNoteAdded`.
- `SessionNote` captures append-only notes with `Text`, `CreatedAtUtc`, optional `RuleId` (null for session notes), and `EvidenceLinks` — a list of evidence references extracted from bracket (`[ref]`) or backtick (`` `ref` ``) syntax in the note text. The syntax is stripped from the stored text so notes remain readable while preserving traceable references.
- `RemediationSessionEventType` enum defines the event kinds.
- `ISessionStore` follows the existing store pattern (`JsonFileSessionStore` + `InMemorySessionStore`). Both round-trip the timeline and session notes.
- Blocked sessions remain persisted for auditability, but the UI does not expose remediation command cards for blocked steps and verification refuses blocked sessions.
- Verification always records a terminal timeline event after `VerificationStarted`: `VerificationCompleted`, `VerificationBlocked`, or `VerificationFailed`. Session export records `Exported` only after the markdown report write succeeds.

### ViewModel Boundaries

- `AgentViewModel` — query dispatch, state, commands. Receives `RemediationPlanBuilder` via constructor for export (not created inline).
- `AgentResultPresenter` — renders `AgentResult` to chat messages.
- `AgentMessageViewModel` — individual message rendering, remediation/session state, and copyable command behavior.
- `MainViewModel` — receives `RemediationPlanBuilder` via constructor for evidence export (not created inline).
- `AgentView.axaml` — exposes Verify Remediation on active session cards, Export Session for the latest session result, and a Remediation Sessions expander with List/Resume/Delete actions.

### Intent Routing

`SecurityAgent.AskAsync` dispatches intents:
- Baseline intents (`SetBaseline`, `CheckDrift`, `ShowBaseline`) -> `BaselineDriftService`
- Remediation intents (`PrioritizeRemediation`, `FixFinding`, `StartRemediation`, `VerifyRemediation`, `ListRemediationSessions`, `ResumeRemediation`) -> `GuidedRemediationService`
- Other follow-up intents -> `AgentFollowUpService`
- Audit intents -> `RunAuditAsync` pipeline

## Logging

Runtime logging is abstracted behind `ILogSink`. The UI uses `DiagnosticsLogSink` to emit to `System.Diagnostics.Trace`, while parsers and engine default to `NullLogSink` if no sink is provided.
