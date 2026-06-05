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
9. The UI renders findings (including timeline and Trace Map visualization), and `EvidenceBuilder` optionally creates a signed bundle that includes a `mitre-navigator-layer.json` built from detector/rule MITRE coverage plus observed finding density.

The **Live Stream** provides a parallel real-time analysis path:

1. `IEventSource` reads live events from `AF_PACKET` + classic BPF, `AF_NETLINK` NFLOG, or a synthetic generator.
2. `LiveStreamWindow` buffers events with dual eviction: 60-second time window and 10 000 event count cap.
3. A dedicated `SentryAnalyzer` instance runs on the window every 5 seconds or 500 events.
4. Completed `LiveAnalysisResult` records flow through a bounded `DropOldest` channel so stale UI updates do not stall analysis.
5. Findings are deduplicated by fingerprint (5-minute TTL) and stored in `LiveFindings` with FIFO eviction at 1 000 entries.
6. `LiveResultReceived` surfaces new findings to the UI, which adds them to the shared findings grid.
7. `StopAsync()` signals cancellation, closes the native socket (unblocking `recv()`), and awaits clean pipeline shutdown.

The **Log Diff** subsystem provides a parallel comparison path for forensic timeline analysis:

1. Two `AnalysisResult` instances are produced by running `SentryAnalyzer` independently on the baseline log and the incident log, using the same intensity profile.
2. `LogDiffAnalyzer.Compare(baseline, incident)` produces a `LogDiffResult` containing:
   - `Events` — per-connection-pattern diff records (`DiffEvent`) matched by a traffic pattern key (source IP + destination IP + destination port + protocol; source port wildcarded because it is commonly ephemeral). Each record carries baseline/incident counts, dominant actions, action histograms, and a `LogDiffState` (`Unchanged`, `Added`, `Removed`, `Changed`). A count delta >20% or a shift in dominant action marks a pattern as `Changed`.
   - `Findings` — per-fingerprint diff records (`DiffFinding`) matched by stable `Finding.Fingerprint`. Baseline-only findings are `Removed`; incident-only are `Added`; severity changes are `Changed`.
   - `Narrative` — a human-readable summary of what changed and why it matters.
   - `Summary` — a concise one-line summary with counts per state.
   - `BaselineLabel` / `IncidentLabel` — descriptive labels, currently file paths in CLI and UI flows, for report formatting.
3. `LogDiffMarkdownFormatter` and `LogDiffHtmlFormatter` render standalone diff reports in GFM and dark-themed HTML.
4. `EvidenceBuilder` includes `log-diff.md` and `log-diff.html` in the signed ZIP when a `LogDiffResult` is provided.
5. The Avalonia UI exposes `LogDiffWindow` with `LogDiffViewModel`, color-coded DataGrids, and `LogDiffStateToBrushConverter` / `LogDiffStateToForegroundBrushConverter` for visual state indication.

The Security Agent provides a parallel local posture path:

1. A natural-language query is parsed into an `AgentIntent`.
2. `ScannerCoordinator` runs agent scanners and builds a `ScanData` snapshot containing firewall, port, service, SSH daemon configuration, file permissions, filesystem audit findings (world-writable files, SUID/SGID binaries, unowned files, sticky-bit checks, /tmp mount options), kernel and system hardening parameters, user accounts, shadow entries, password aging, PAM configuration (password-stack and auth-stack configs, `pwquality.conf`, `faillock.conf`), logging and audit configuration (rsyslog, journald, auditd rules, logrotate, central forwarding), cron job entries and script permissions, installed package inventory and pending security updates (via dpkg, apt, and optionally debsecan for CVE enrichment), unattended-upgrades configuration, interface, route, connection state, container runtime state (Docker/containerd availability, running containers, privileged mode, image tags, socket exposure/mounts, risky base-image hints, namespace isolation), Kubernetes pod security posture (privileged pods, hostNetwork/hostPID/hostIPC sharing, root containers, missing security contexts), live process runtime state (memory maps, environment variables, executable paths, command lines, parent-child relationships, and duplicate-field / truncation metadata from `/proc/<pid>/`), YARA rule matches for SUID/SGID binaries, running process executables, and cron scripts, and data-source capability status for local Linux commands.
3. `RuleEvaluationService` filters rules by intent, resolves role-aware policy from built-in defaults and local JSON overrides, invokes contextual rules when supported, converts rule crashes into explicit results, and applies auto-pass or severity override policy.
4. `FindingAssemblyService` converts failed posture checks into `Finding` records with stable fingerprints, markdown-backed explanations, suppression status, and **dual-layer CIS Benchmark mappings** (CIS Controls v8 + CIS Ubuntu 24.04 LTS technical controls).
5. `AgentLogAnalysisService` optionally analyzes pasted firewall logs through `SentryAnalyzer`.
6. `AgentResultComposer` builds user-facing summaries and deterministic data-source capability reports.
7. `AgentResultFinalizer` attaches `ComplianceScorecardBuilder` and `RiskScorecardBuilder` output, builds the final `AgentResult`, and updates `AgentAuditState` for follow-up questions.
8. `AgentFollowUpService`, `FindingExplanationService`, and `BaselineDriftService` answer deterministic follow-up questions, selected-finding explanations, baseline save/show, and drift comparison without making `SecurityAgent` own those workflows directly.
9. `AuditDiffCalculator` compares audit snapshots for history diffs and baseline drift detection.
10. `IBaselineStore` persists user-designated known-good baselines; `JsonFileBaselineStore` writes to `~/.config/VulcansTrace/baselines.json`.
11. `AgentReportGenerator` can adapt agent results back into `AnalysisResult`.
- `FindingAssemblyService` maps `RuleResult.MitreTechniques` to `Finding.MitreTechniques` so agent posture findings carry MITRE ATT&CK context through every export path.
- `RemediationMarkdownFormatter` renders exported session reports with a `## Notes` section that groups session notes and step notes (by rule ID), showing timestamps, text, and extracted evidence links. Remediation plan exports include an `## Impact Preview` block per section showing expected impact, rollback path, and verification command. Remediation sections now also carry `MitreTechniques` for threat-contextualized remediation planning.

The **Auto-Fix pipeline** extends the Security Agent to headless batch remediation:

1. `RemediationPlanBuilder` constructs a `RemediationPlan` from agent `Finding` records by parsing explanation templates into structured sections.
2. `CommandSafetyClassifier` analyzes each extracted command and labels it `ReadOnly`, `ConfigChange`, `ServiceRestart`, `PackageInstall`, `Destructive`, or `Unknown`.
3. `AutoFixPolicy` defines which safety classifications are permitted for automatic execution (configurable via `--allow-restart` and `--allow-packages`).
4. `RemediationPlanValidator` blocks sections where risky or unclassified commands lack explicit rollback guidance.
5. `RemediationExecutor` orchestrates the execution: backup commands first, then apply commands, then verification commands. If an apply command fails, rollback commands are executed automatically. Cancellation is checked before every command.
6. `ProcessRunner` executes shell commands via bash stdin (not `-c` argument wrapping) to avoid shell escaping vulnerabilities, with configurable timeout and cancellation support.
7. `RemediationConsoleFormatter` renders dry-run previews and execution results for CLI output.

The **Automated Incident Response Playbooks** layer extends the Trace Map correlation engine with active countermeasures:

1. `TraceMapCorrelator` detects critical attack chains — a Beaconing → LateralMovement → PrivilegeEscalation triplet on the same host within a correlated time window — and produces a `CriticalChain` record with chronologically sorted `FindingIds`.
2. `RemediationPlanBuilder.BuildCountermeasures(TraceMapResult)` looks up findings by category (not positional index) to extract the attacker's C2 IP from the Beaconing finding's `Target` field.
3. The attacker IP is parsed and validated before any commands are generated; invalid IPs produce a `COUNTERMEASURE-BLOCKED` section with a clear risk note instead of potentially malformed shell commands.
4. Valid attacker IPs generate two countermeasure commands:
   - `IptablesDrop`: `iptables -A INPUT -s <attackerIp> -j DROP` or `ip6tables -A INPUT -s <attackerIp> -j DROP` with matching rollback
   - `AuditdMonitor`: `auditctl -a always,exit -F arch=b64 -S connect -k vulcanstrace_countermeasure_<ip>` with rollback `auditctl -d ...`
5. Countermeasure commands are deduplicated by attacker IP via a `HashSet<string>` so multiple critical chains targeting the same C2 IP produce only one section.
6. Verification uses an exact firewall rule check (`iptables -C ...` or `ip6tables -C ...`) rather than `grep`, so verification succeeds only when the rule is actually present in the kernel's netfilter tables.
7. Both countermeasure commands are added to `RemediationSection.ApplyCommands` so the `RemediationExecutor` actually executes them during live deployment.
8. The Avalonia UI surfaces a **Deploy Countermeasures** button on critical chain messages. Clicking it runs a dry-run preview first, then shows a confirmation dialog (Deploy Live / Cancel), and only then executes the plan live. Dry-run results are posted to the chat panel.
9. Auditd connect syscall rules are tagged for later correlation because auditd cannot filter `connect` events by remote IP address directly.

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
- `LogDiffResult`: baseline-vs-incident comparison output with diff events, diff findings, narrative, and summary counts.
- `DiffEvent`: per-connection-pattern diff record with baseline/incident counts, dominant actions, action histograms, and `LogDiffState`.
- `DiffFinding`: per-fingerprint diff record with baseline/incident severity and `LogDiffState`.
- `LogDiffState`: `Unchanged`, `Added`, `Removed`, or `Changed`.
- `MitreTechnique`: MITRE ATT&CK technique mapping with `TechniqueId`, `TechniqueName`, `Tactic`, and `WhyItMatters`. Validated at construction (non-empty IDs).
- `MitreLayerBuilder`: builds MITRE ATT&CK Navigator v4.5-compatible layer JSON from findings, with deterministic technique aggregation (most common name wins, alphabetical tiebreak) and gradient scoring.
- `LiveAnalysisResult`: real-time analysis output containing delta findings (new since last run), window metrics, and source status.
- `LiveWindowMetrics`: live stream statistics (event rate, window size, analysis run count).
- `IThreatIntelStore`: abstraction for offline IOC storage with add, clear, and query-by-type operations.
- `IocEntry`: immutable IOC record (`Type`, `Value`, `Confidence`, `Source`, `ImportedAtUtc`).
- `CriticalChain`: record representing a detected critical attack chain (Beaconing → LateralMovement → PrivilegeEscalation) on a single host, with chronologically sorted `FindingIds`.
- `CountermeasureCommand`: record representing an active defense command (`IptablesDrop` or `AuditdMonitor`) with apply command, rollback command, safety classification, and target host.
- `CountermeasureType`: enum discriminating `IptablesDrop` and `AuditdMonitor` countermeasure kinds.
- `FileHashEntry`: scanner output pairing a file path with its SHA-256 hash (`Path`, `Hash`, `Algorithm`).
- `YaraMatchEntry`: scanner output for a YARA rule match, including the target path, target kind, matching rule identifier, optional process ID, and optional match description.

## Detection Layers

Baseline detectors:
- PortScan, Flood, LateralMovement, Beaconing, PolicyViolation, Novelty.

Linux Deep Inspection detectors:
- FlagAnomaly, MacSpoofing, KernelModule, InterfaceHopping, UnusualPacketSize.

Advanced threat detectors:
- C2Channel, PrivilegeEscalation.
- ThreatIntelDetector — correlates firewall logs and live stream events against imported IOCs (STIX/MISP).

## Threat Intel Components

- `IThreatIntelStore` — abstraction for IOC storage (`InMemoryThreatIntelStore` + `JsonFileThreatIntelStore` → `~/.config/VulcansTrace/threat-intel.json`).
- `IocEntry` — immutable IOC record with `Type`, `Value`, `Confidence`, `Source`, `ImportedAtUtc`.
- `IocType` — `IPv4`, `IPv6`, `Domain`, `URL`, `Port`, `FileHash`.
- `StixParser` — parses STIX 2.1 bundle JSON, extracting IOCs from `ipv4-addr`, `ipv6-addr`, `domain-name`, `url`, `file` objects, and simple or compound `indicator` equality patterns.
- `MispParser` — parses MISP event JSON, reading `Event.Attribute` and `Event.Object.Attribute`, mapping MISP types to `IocType`.
- `FileHashEntry` — scanner output pairing a file path with its SHA-256 hash.
- `FileHashScanner` — discovers security-sensitive files (SUID/SGID, world-writable, unowned, cron scripts) and hashes them via `sha256sum`/`openssl` only when file-hash IOCs are loaded.
- `ThreatIntelDetector` (Engine) — implements `IDetector`; checks `UnifiedEvent.SourceIP`, `DestinationIP`, and `DestinationPort` against the store. Domain and URL IOCs are stored but not yet correlated in firewall log analysis (the log format does not reliably carry those fields).
- Threat intel rules (Agent):
  - `TI-001` (`ThreatIntelIpRule`) — active connections matching IP IOCs.
  - `TI-002` (`ThreatIntelPortRule`) — open ports matching port IOCs.
  - `TI-003` (`ThreatIntelHashRule`) — file hashes matching hash IOCs.
- AgentFactory wires the store into `ThreatIntelDetector`, all three rules, and `FileHashScanner`.

## YARA Components

- `IYaraEngine` — testable abstraction around YARA rule compilation and file scanning.
- `LibyaraEngine` — thin P/Invoke wrapper over `libyara.so.10` with `DllImportResolver` fallback to `libyara.so`. Registers a one-time `yr_initialize()` and exposes `CompileRules` plus `ScanFile` with a C# callback that marshals matching rule identifiers.
- `YaraScanner` — discovers targets (`find` for SUID/SGID, `/proc/<pid>/exe` symlink resolution, cron script directories), deduplicates by path, scans with bounded concurrency, and populates `YaraMatchEntry` records on `ScanDataBuilder`. Bundled rules ship as an embedded resource; optional custom rules load from `~/.config/VulcansTrace/yara/*.yar`.
- `YaraMatchRule` (`YARA-001`) — fails when any YARA match is present on a SUID/SGID binary, running process executable, or cron script, with severity `High` and MITRE ATT&CK `T1204.002` / `T1027` mappings.
- AgentFactory wires `YaraScanner` and `YaraMatchRule` into the agent pipeline; `RuleEvaluationService` filters by `FindingCategories.Yara` for `AgentIntent.YaraCheck`.

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
