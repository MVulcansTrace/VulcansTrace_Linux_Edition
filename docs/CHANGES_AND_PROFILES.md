# VulcansTrace Linux Edition - Change Summary and Profile Capabilities

This document summarizes the changes added in this branch and describes the
current analysis profiles (Low, Medium, High), including the detectors they
enable and the thresholds they use. It is intended as a concise portfolio
reference and a technical verification checklist.

Last updated: 2026-06-21

### Security Agent — Adaptive Remediation, Diagnostic Dialogue, and CLI Audit Skip

- **Adaptive step-outcome reporting** — users can report the result of a manual remediation step in natural language (`step 1 worked`, `step 2 failed with permission denied`, `it didn't work`, `that worked`). `StepOutcomeParser` deterministically classifies success/failure, step ordinal, rule ID, and failure reason; `GuidedRemediationService` resolves the target rule by ordinal, rule ID, current active session, or explicit session ID; updates the session timeline; and returns adaptive guidance from `FailureResponseTable`. Failures are categorized as `PermissionIssue`, `MissingDependency`, `ServiceMissing`, `MalformedCommand`, `AlreadyConfigured`, or `UnknownFailure`, and responses cite the actual command that was reported on. The cleaned failure reason falls back to the original raw query for classification when the cleaned text loses trigger words such as "failed to start".
  - Code: `VulcansTrace.Linux.Agent/Remediation/StepOutcomeParser.cs`, `StepOutcome.cs`, `FailureClassifier.cs`, `FailureCategory.cs`, `FailureResponseTable.cs`, `VulcansTrace.Linux.Agent/Reports/GuidedRemediationService.cs`, `VulcansTrace.Linux.Agent/Sessions/RemediationSession.cs`, `VulcansTrace.Linux.Agent/SecurityAgent.cs`
  - Tests: `VulcansTrace.Linux.Tests/Agent/Remediation/StepOutcomeParserTests.cs`, `FailureClassifierTests.cs`, `FailureResponseTableTests.cs`, `GuidedRemediationServiceTests.cs`, `RemediationSessionIntegrationTests.cs`

- **Diagnostic dialogue & recurrence root-cause matching** — `DiagnosticDialogueService` drives a structured, deterministic investigation when a rule keeps recurring. It asks category-specific diagnostic questions, maps free-text answers to root-cause buckets (`ConfigManagement`, `NonPersistent`, `Uncertain`, or `Unknown`) via `RootCauseMatcher`, and produces targeted guidance (for example, fix the Ansible playbook or cloud-init user-data instead of the live system). State is tracked in `DialogueState` and persisted through `AgentMemorySnapshot`.
  - Code: `VulcansTrace.Linux.Agent/Dialogue/DiagnosticDialogueService.cs`, `DiagnosticQuestionBank.cs`, `DialogueState.cs`, `RootCauseMatcher.cs`
  - Tests: `VulcansTrace.Linux.Tests/Agent/Dialogue/DiagnosticDialogueServiceTests.cs`, `DiagnosticQuestionBankTests.cs`, `RootCauseMatcherTests.cs`

- **CLI audit skip** — `vulcanstrace ask` no longer runs a redundant pre-audit for queries that are conversational, remediation-related, or already imply their own audit. `IAgent.ResolveQuery` and `IAgent.LastResult` expose the resolved intent and prior audit context; `AgentIntentExtensions.IsAuditIntent` and `ShouldRunAuditBeforeAsk` decide when a pre-audit is actually needed. Explicit audit queries (`firewall check`, `full audit`) are executed by `AskAsync` itself, so no duplicate scan runs.
  - Code: `VulcansTrace.Linux.Agent/IAgent.cs`, `VulcansTrace.Linux.Agent/SecurityAgent.cs`, `VulcansTrace.Linux.Agent/Query/AgentIntentExtensions.cs`, `VulcansTrace.Linux.Cli/Program.cs`
  - Tests: `VulcansTrace.Linux.Tests/Cli/AskCommandTests.cs`

- **Cross-scanner validator exclusions** — container rules (`CTR-001`–`CTR-005`) and Kubernetes rules (`K8S-001`–`K8S-004`) are no longer registered in `CrossScannerValidator` because they draw from the same `docker`/`crictl`/`kubectl` scanner data a validator would read. Validating them would be tautological, so they are excluded on the same grounds as `FW-001`, `FW-004`, and `NET-003`. The registry was also expanded with validators for `SRV-002`, `SRV-004`, and additional SSH rules (`SSH-001`, `SSH-004`, `SSH-005`, `SSH-006`).
  - Code: `VulcansTrace.Linux.Agent/Analysis/CrossScannerValidator.cs`
  - Tests: `VulcansTrace.Linux.Tests/Agent/Analysis/CrossScannerValidatorTests.cs`

- **Query-parser hardening** — `QueryParser.StepOutcomePattern` now requires an explicit subject (`step N` or `it`/`that`) so bare outcome words like "failed" or "completed" in ordinary audit queries no longer misroute to `ReportStepResult`. Bare `"again"` was removed from the recurrence matcher so phrases like "explain FW-001 again" and "run the firewall audit again" no longer misroute to `InvestigateRecurrence`. `StepOutcomeParser` now treats negated error phrases (`no error`, `error-free`, `zero errors`) as success reports.
  - Code: `VulcansTrace.Linux.Agent/Query/QueryParser.cs`, `VulcansTrace.Linux.Agent/Dialogue/IntentInferenceEngine.cs`, `VulcansTrace.Linux.Agent/Remediation/StepOutcomeParser.cs`
  - Tests: `VulcansTrace.Linux.Tests/Agent/QueryParserTests.cs`, `IntentInferenceEngineTests.cs`, `StepOutcomeParserTests.cs`

- **Guided-remediation fixes** — `ResolveRuleIdByStepOrdinal` now maps an out-of-section ordinal to the Nth apply-command of a single-section plan, matching the step-by-step command list the user sees. The failure response displays the command the user actually reported on. `Verified` status is now sticky on redundant completed/skipped marks but still reopens to `Active` on failure.
  - Code: `VulcansTrace.Linux.Agent/Reports/GuidedRemediationService.cs`
  - Tests: `VulcansTrace.Linux.Tests/Agent/GuidedRemediationServiceTests.cs`

### Security Agent — Provenance On Demand and Audit History Slimming

- Added `ShowEvidence` intent and `EvidenceProvenanceService` so users can ask for a deterministic evidence chain for any cached finding (e.g. `prove FW-002`, `show evidence for it`, `what triggered FW-002?`). The response assembles scanner source/commands, raw evidence signals, cross-scanner validation, rule evaluation, CIS/MITRE context, attack-chain membership, and per-rule history without calling an LLM; if a known rule ID is not cached, the single-rule fallback can collect fresh scanner data.
- Added `ReferenceResolver` so bare category words (`explain SSH`, `show evidence SSH`) resolve to the focused finding when its category matches, making `ExplainFinding` and `ShowEvidence` behave consistently after an explanation.
- Persisted `DataSourceCapabilities` and `AttackChains` in `AuditHistoryEntry` so provenance survives process restarts/rehydration.
- Fixed `RunAuditCoreAsync` so `RememberAudit` is called after all enrichments (posture correlations, attack chains, trajectory, narrative) are applied. This guarantees `LastResult` contains the fully enriched result the user sees, while the history entry persists the fields needed for restart/follow-up provenance such as findings, capabilities, rule results, warnings, log analysis, scorecard, and attack chains.
- Hardened `QueryParser` evidence routing with a higher `ShowEvidence` weight so phrases like `show me the evidence` win over filter intents without relying on tuple order.
- Hardened `EvidenceProvenanceService` capability matching with priority scoring (exact → first-token → substring, longest-name tie-break) so short tokens like `ss` never shadow `sshd_config` or `sshd -T`.
- Improved markdown escaping for backticks in inline code spans.
- Added audit-history slimming: `JsonFileAuditHistoryStore` and `InMemoryAuditHistoryStore` keep the newest 5 entries fully detailed and replace older retained entries with slim summaries that preserve counts, `SnapshotFindings`, and `Scorecard` while dropping verbose fields. This keeps `audit-history.json` bounded as per-entry metadata grows.
- Added `IsSlimSummary` and `ToSlimSummary()` to `AuditHistoryEntry`; added a guard in `SecurityAgent.RehydrateLastResult` so slim entries are not rehydrated as the live `LastResult`.
  - Code: `VulcansTrace.Linux.Agent/Query/QueryParser.cs`, `VulcansTrace.Linux.Agent/Dialogue/ReferenceResolver.cs`, `VulcansTrace.Linux.Agent/Reports/EvidenceProvenanceService.cs`, `VulcansTrace.Linux.Agent/Reports/AuditHistoryEntry.cs`, `VulcansTrace.Linux.Agent/Reports/JsonFileAuditHistoryStore.cs`, `VulcansTrace.Linux.Agent/Reports/InMemoryAuditHistoryStore.cs`, `VulcansTrace.Linux.Agent/Reports/AgentResultFinalizer.cs`, `VulcansTrace.Linux.Agent/Reports/SingleRuleExplanationService.cs`, `VulcansTrace.Linux.Agent/SecurityAgent.cs`
  - Tests: `VulcansTrace.Linux.Tests/Agent/EvidenceProvenanceServiceTests.cs`, `QueryParserTests.cs`, `FindingExplanationServiceTests.cs`, `JsonFileAuditHistoryStoreTests.cs`, `AgentResultFinalizerTests.cs`, `SecurityAgentTests.cs`, `SecurityAgentDialogueIntegrationTests.cs`

### Security Agent — Long-Horizon Category Coverage Tracking

- Added `CategoryAuditEntry`, `CategoryCoverageRecorder`, and `IntentCategoryMap` in `VulcansTrace.Linux.Agent/Memory/` and `VulcansTrace.Linux.Agent/Query/` to track which of the 17 targeted audit categories have been checked across turns and sessions.
- `FullAudit` marks all 17 categories (`Firewall`, `Network`, `Service`, `Port`, `SSH`, `FilePermission`, `FilesystemAudit`, `Kernel`, `UserAccount`, `Logging`, `CronJob`, `PackageVulnerability`, `Container`, `Kubernetes`, `ThreatIntel`, `Yara`, `ProcessRuntime`) as checked; each targeted intent marks exactly one category.
- Extended `AgentMemorySnapshot` and `EntityFrame` with `CheckedCategories`; wired save/restore in `SecurityAgent` and `DialogueContext` so coverage survives application restarts and is reset only when the conversation frame is explicitly cleared.
- `NarrativeComposer` appends a **Coverage note** paragraph after partial audits, listing categories already audited and the next unchecked areas.
- `AgentSuggestionProvider` emits one blind-spot follow-up chip for the first unchecked category after a targeted audit (e.g. `Check filesystem security`, `Check running processes`), using disambiguating queries such as `check ssh config` for the SSH category.
- Speculative-audit wrappers (`BaselineDriftService`, `GuidedRemediationService`, `AgentFollowUpService`) preserve cumulative coverage and rule history via `DialogueContext.RestoreState(..., preserveCoverage: true, preserveRuleHistory: true)`, so drift checks, verification re-audits, and filter-category fallback audits do not erase long-horizon memory.
- Robustness fixes: guarded `ComposeCoverage` against empty coverage, reset `CheckedCategories` in `EntityFrame.Clear()`, enabled `PropertyNameCaseInsensitive` in `JsonFileAgentMemoryStore` for legacy PascalCase files.
- Tests cover coverage recording for full and targeted audits, narrative rendering, suggestion generation, JSON round-trip, PascalCase binding, `RestoreState` preservation semantics, and drift-check memory retention.
  - Code: `VulcansTrace.Linux.Agent/Memory/CategoryAuditEntry.cs`, `CategoryCoverageRecorder.cs`, `IntentCategoryMap.cs`, `VulcansTrace.Linux.Agent/Memory/AgentMemorySnapshot.cs`, `VulcansTrace.Linux.Agent/Dialogue/EntityFrame.cs`, `DialogueContext.cs`, `NarrativeComposer.cs`, `AgentSuggestionProvider.cs`, `BaselineDriftService.cs`, `GuidedRemediationService.cs`, `AgentFollowUpService.cs`, `JsonFileAgentMemoryStore.cs`
  - Tests: `VulcansTrace.Linux.Tests/Agent/Memory/CategoryCoverageRecorderTests.cs`, `JsonFileAgentMemoryStoreTests.cs`, `NarrativeComposerTests.cs`, `Agent/Suggestions/AgentSuggestionProviderTests.cs`, `Agent/Memory/SecurityAgentMemoryIntegrationTests.cs`

### Doctor — Data-Source Self-Diagnostic
- Added `DoctorService` and `DoctorResult` in `VulcansTrace.Linux.Agent/Diagnostics/` that run the same `ScannerCoordinator` used during audits in read-only probe mode and produce normalized capability rows plus deterministic capability reports via `AgentResultComposer`.
- CLI `vulcanstrace doctor [--output-json <file>]` probes all local scanner data sources, prints a color-coded summary, and exits with:
  - `0` — all normalized data sources reported `Available`.
  - `1` — at least one normalized data source reported `Unavailable` or a runtime error occurred.
  - `2` — at least one normalized data source reported `PermissionLimited` or `Unknown`, with none `Unavailable`.
  - `130` — cancelled by the user (`OperationCanceledException`).
- Avalonia UI adds a dedicated **Doctor** tab (`DoctorView` + `DoctorViewModel` + `DoctorCapabilityViewModel`) bound to the same `DoctorService`. The view shows a summary status banner, a warnings banner for scanner failures or permission limits, and a normalized capability grid. An empty-state prompt is shown before the first run; a `HasProbed` flag ensures zero-capability results still show the summary rather than the onboarding prompt.
- Detail truncation is surrogate-safe via `StringInfo.SubstringByTextElements` so capability details with surrogate pairs are not corrupted.
- Tests cover service probing, normalized capability ordering, availability exit-code mapping, empty/warning states, ViewModel loading, cancellation handling, JSON export, and CLI argument routing.
  - Code: `VulcansTrace.Linux.Agent/Diagnostics/DoctorService.cs`, `VulcansTrace.Linux.Agent/Diagnostics/DoctorResult.cs`, `VulcansTrace.Linux.Avalonia/ViewModels/DoctorViewModel.cs`, `VulcansTrace.Linux.Avalonia/ViewModels/DoctorCapabilityViewModel.cs`, `VulcansTrace.Linux.Avalonia/Views/DoctorView.axaml`, `VulcansTrace.Linux.Cli/Program.cs`, `VulcansTrace.Linux.Agent/AgentFactory.cs`, `VulcansTrace.Linux.Agent/AgentServices.cs`
  - Tests: `VulcansTrace.Linux.Tests/Agent/DoctorServiceTests.cs`, `VulcansTrace.Linux.Tests/Avalonia/DoctorViewModelTests.cs`, `VulcansTrace.Linux.Tests/Cli/DoctorCommandTests.cs`

### Remediation Impact Simulator
- Added `RemediationImpactSimulator` static service that analyzes `RemediationSection` records before display or execution and derives pre-flight risk metrics: risk before (from finding severity), expected risk after, command count (distinct apply + backup + countermeasure commands), rollback availability, restart impact, and lockout risk.
- **Restart impact detection**: identifies commands with `CommandSafety.ServiceRestart` or matching `systemctl restart/reload/try-restart/force-reload` patterns (with word-boundary guards and shell-comment stripping to avoid false positives).
- **Lockout risk detection**: identifies commands touching SSH configuration (`sshd_config`, `/etc/ssh/`), iptables DROP on port 22 or default INPUT policy, and UFW deny rules — using individual regexes with `\s+` whitespace tolerance and ordered from most specific to least specific.
- **ReadOnly gate**: ReadOnly-classified commands are skipped for both restart and lockout analysis, preventing false positives from inspection commands such as `cat /etc/ssh/sshd_config`.
- **Aggregation**: multiple matching commands accumulate descriptions (joined with `" | "`) rather than shadowing later, more dangerous commands with an early first-match.
- **Apply-impact command analysis**: the simulator scans distinct ApplyCommands, BackupCommands, and CountermeasureCommands (adapted to `RemediationCommand`) for restart and lockout impact. Verification and rollback commands are excluded because they run after apply or during recovery.
- **Fault isolation**: `RemediationPlanBuilder` wraps each `Simulate` call in `try/catch` so a malformed section degrades gracefully without aborting the entire plan.
- **Countermeasure-only fix**: `BuildExpectedRiskAfter` now only checks `ApplyCommands.Count`, so countermeasure-only sections correctly report "Manual review required" instead of falsely claiming resolution.
- **Severity parser fix**: replaced `Contains`-based severity extraction with a deterministic `^\[([A-Za-z]+)\]` regex bracket extraction, eliminating false positives such as "[Low] Non-Critical" → "Critical".
- **Avalonia UI**: expanded the Impact Preview card with risk before/after, command count, explicit rollback availability, and conditional RESTART (orange), LOCKOUT (red), ROLLBACK (green), and NO ROLLBACK (red) badges.
- **CLI**: `RemediationConsoleFormatter.FormatDryRun` and `Program.cs` live preview now render all six simulation fields.
- **Markdown export**: `RemediationMarkdownFormatter` includes risk before/after, command count, rollback availability, restart impact, and lockout risk in the `## Impact Preview` block.
- **Tests**: 25 simulator unit tests, 2 plan-builder integration tests, 3 ViewModel binding tests, 1 markdown formatter test, and 1 JSON round-trip test for impact preview field persistence.
  - Code: `VulcansTrace.Linux.Agent/Reports/RemediationImpactSimulator.cs`, `VulcansTrace.Linux.Agent/Reports/RemediationPlanBuilder.cs`, `VulcansTrace.Linux.Agent/Reports/RemediationMarkdownFormatter.cs`, `VulcansTrace.Linux.Agent/Remediation/RemediationConsoleFormatter.cs`, `VulcansTrace.Linux.Cli/Program.cs`, `VulcansTrace.Linux.Avalonia/ViewModels/AgentMessageViewModel.cs`, `VulcansTrace.Linux.Avalonia/AgentView.axaml`
  - Tests: `VulcansTrace.Linux.Tests/Agent/RemediationImpactSimulatorTests.cs`, `VulcansTrace.Linux.Tests/Agent/RemediationPlanBuilderTests.cs`, `VulcansTrace.Linux.Tests/Avalonia/AgentMessageViewModelTests.cs`, `VulcansTrace.Linux.Tests/Agent/RemediationMarkdownFormatterTests.cs`, `VulcansTrace.Linux.Tests/Agent/RemediationSessionIntegrationTests.cs`

## 1) Changes Added (What Was Implemented)

### Automated Incident Response Playbooks
- **Critical Chain Detection**: `TraceMapCorrelator` detects Beaconing → LateralMovement → PrivilegeEscalation triplets on the same host and produces `CriticalChain` records with chronologically sorted `FindingIds`.
  - Code: `VulcansTrace.Linux.Engine/TraceMapCorrelator.cs`
- **Countermeasure Generation**: `RemediationPlanBuilder.BuildCountermeasures(TraceMapResult)` generates active defense commands:
  - `IptablesDrop`: blocks the attacker's C2 IP with `iptables -A INPUT -s <ip> -j DROP` or `ip6tables -A INPUT -s <ip> -j DROP`
  - `AuditdMonitor`: tags connect telemetry with `auditctl -a always,exit -F arch=b64 -S connect -k vulcanstrace_countermeasure_<ip>` for analyst correlation
  - Code: `VulcansTrace.Linux.Agent/Reports/RemediationPlanBuilder.cs`
- **Safety and Validation**:
  - Attacker IP extracted from Beaconing `Target` and validated before command generation
  - Invalid IPs produce `COUNTERMEASURE-BLOCKED` sections instead of malformed shell commands
  - Duplicate attacker IPs deduplicated via `HashSet<string>` across multiple critical chains
  - Verification uses `iptables -C` exact-rule checking (not `grep`)
  - Countermeasure commands populate `ApplyCommands` so `RemediationExecutor` actually executes them
- **UI Integration**: Avalonia UI shows **Deploy Countermeasures** button on critical chain messages. Workflow: dry-run preview → confirmation dialog → live execution. Results posted to chat panel.
  - Code: `VulcansTrace.Linux.Avalonia/ViewModels/AgentViewModel.cs`, `AgentView.axaml`
- **Tests**: 4 new tests covering critical chain generation, out-of-order timestamp handling, invalid IP rejection, and attacker-IP deduplication. 2 updated view-model tests verifying `FakeProcessRunner` invocation during live execution.
  - Code: `VulcansTrace.Linux.Tests/Engine/TraceMapCorrelatorTests.cs`, `VulcansTrace.Linux.Tests/Agent/RemediationPlanBuilderTests.cs`, `VulcansTrace.Linux.Tests/Avalonia/AgentViewModelTests.cs`

### Detection and analysis
- C2 Channel Detection: tightened grouping (ignore source port) and guarded
  against invalid tolerance values.
  - Code: `VulcansTrace.Linux.Engine/Detectors/C2ChannelDetector.cs`
- Privilege Escalation Detector: refocused on suspicious admin port access
  spikes and sweeps with a per-profile spike window.
  - Code: `VulcansTrace.Linux.Engine/Detectors/PrivilegeEscalationDetector.cs`
- Flag Anomaly Detector: eliminated false positives when TCP flags are missing.
  - Code: `VulcansTrace.Linux.Engine/Detectors/FlagAnomalyDetector.cs`

### Detection Confidence Scoring
- Added `DetectionConfidence` enum (`Unknown`, `Low`, `Medium`, `High`, `Confirmed`) to Core for explicit confidence levels on every finding.
- Added `EvidenceSignal` immutable record (`Name`, `Source`, `Explanation`) representing individual pieces of supporting evidence. Source constants: `BehaviorSource` (detector-derived) and `ThreatIntelSource` (IOC-matched).
- Added `FindingConfidenceCalculator` in Engine that maps evidence signals to confidence levels: 0 signals → `Unknown`, 1 → `Low`, 2 → `Medium`, 3+ → `High`, simultaneous `ThreatIntel` + `Behavior` → `Confirmed`.
- All 14 engine detector implementations and the agent `FindingAssemblyService` now populate `EvidenceSignals` and call `FindingConfidenceCalculator` before emitting findings.
- `ThreatIntelDetector` emits `ThreatIntelSource` signals; all other detectors emit `BehaviorSource` signals with detector-specific explanations.
- `RiskEscalator` recalculates confidence when escalating findings to Critical: appends a `Cross-detector correlation` behavior signal and re-runs the calculator, so escalated findings reflect the stronger combined evidence.
- `Finding.Confidence` defaults to `Unknown` and is excluded from `Fingerprint` and `Id` to keep stable identity across confidence changes.
- `IocEntry.Confidence` renamed to `ThreatScore` (int 0–100) to eliminate naming collision with detection confidence. Updated parser, rules, tests, and docs.
- All 5 evidence formatters (CSV, HTML, Markdown, JSON, STIX) export `Confidence` and `EvidenceSignals` alongside severity and category.
- Avalonia UI `FindingItemViewModel` exposes confidence for display; DataGrid and Agent chat cards include confidence and evidence signal names; text search covers confidence and evidence signal names.
- Audit history, audit diff, baseline drift, scheduled audit snapshots, and remediation verification snapshots preserve confidence metadata. Confidence-only audit changes appear in the Audit Diff window, except support-only `Low` ↔ `Medium` transitions: because agent rule findings start at `Low` and commonly reach `Medium` via one cross-scanner support signal, those transitions are treated as scanner-availability churn rather than a meaningful state change. Contradiction-driven confidence drops still surface.
- Code: `VulcansTrace.Linux.Core/DetectionConfidence.cs`, `EvidenceSignal.cs`, `IocEntry.cs`
- Code: `VulcansTrace.Linux.Engine/Confidence/FindingConfidenceCalculator.cs`, `RiskEscalator.cs`
- Code: `VulcansTrace.Linux.Agent/Reports/FindingAssemblyService.cs`
- Code: `VulcansTrace.Linux.Evidence/Formatters/*.cs`
- Code: `VulcansTrace.Linux.Avalonia/ViewModels/FindingItemViewModel.cs`, `VulcansTrace.Linux.Avalonia/ViewModels/AgentResultPresenter.cs`, `VulcansTrace.Linux.Avalonia/MainWindow.axaml`, `VulcansTrace.Linux.Avalonia/AgentView.axaml`
- Tests: `FindingConfidenceCalculatorTests`, `FindingsViewModelTests`, evidence formatter tests, `AuditDiffCalculatorTests`, `AgentResultPresenterTests`, `AgentHistoryCoordinatorTests`

### Evidence and export formats
- STIX 2.1 export rebuilt: now emits a STIX bundle with identity,
  observed-data, note objects, IP observables, and optional malware hints.
  - Code: `VulcansTrace.Linux.Evidence/Formatters/StixFormatter.cs`
- Trace Map evidence export: when findings are present, the signed ZIP bundle includes `incident-story.md` (flowing attack narrative); when correlated edges are present, it also includes `trace-map.md` (technical edge-list) and `trace-map.json` (Cytoscape.js-compatible graph with nodes and edges).
  - Code: `VulcansTrace.Linux.Evidence/Formatters/IncidentStoryFormatter.cs`
  - Code: `VulcansTrace.Linux.Evidence/Formatters/TraceMapMarkdownFormatter.cs`
  - Code: `VulcansTrace.Linux.Evidence/Formatters/TraceMapJsonFormatter.cs`
  - Code: `VulcansTrace.Linux.Evidence/EvidenceBuilder.cs`
- Evidence bundle validation added to the CLI utility.
  - Code: `tools/TestAnalysis/Program.cs`

### Finding Deduplication + Noise Budget
- Replaced the old per-category truncation (`ApplyFindingCap`) with a noise-budget grouping pipeline (`ApplyNoiseBudget`).
- Findings are grouped by a semantic noise key. Rule-backed findings use rule ID, category, source host, and short description so repeated findings with different targets collapse into one representative. Detector findings without a rule ID also include details, keeping distinct C2 intervals separate.
- Each group produces a representative `Finding` enriched with:
  - `GroupedCount` — how many raw findings were collapsed into this group (default 1, always ≥ 1)
  - `RepresentativeTargets` — up to 5 distinct targets from the grouped findings
  - `RiskDrivers` — top 3 directories for path targets, extracted IPs for IP:port targets, or top source hosts as fallback
- The per-category cap (`MaxFindingsPerDetector = 100`) now limits group count, not raw findings. When the budget is exceeded, a warning is emitted: `"X detector produced N findings, grouped into M representatives (showing top K)."`
- Representatives are ordered by severity desc, then grouped count desc, then fingerprint for deterministic selection.
- `DeriveRiskDrivers` handles IPv4, IPv6 (bracket notation), and path targets with strict validation — malformed inputs fall back to source hosts.
- All 5 evidence formatters (CSV, HTML, Markdown, JSON, STIX) include `GroupedCount`, `RepresentativeTargets`, and `RiskDrivers` in their output.
- Avalonia UI shows grouping in both the Agent chat and the findings DataGrid, with a count badge when `GroupedCount > 1`.
- Code: `VulcansTrace.Linux.Core/Finding.cs`
- Code: `VulcansTrace.Linux.Engine/SentryAnalyzer.cs`
- Code: `VulcansTrace.Linux.Evidence/Formatters/*.cs`
- Code: `VulcansTrace.Linux.Avalonia/ViewModels/FindingItemViewModel.cs`, `MainWindow.axaml`
- Tests: `NoiseBudgetTests` (11 unit tests + integration coverage), `SecurityAgentTests`, and evidence formatter tests for grouping metadata

### UI and UX
- Timeline visualization: normalized placement, severity-based colors,
  time-range label, and tooltip detail.
  - Code: `VulcansTrace.Linux.Avalonia/ViewModels/TimelineViewModel.cs`
  - Code: `VulcansTrace.Linux.Avalonia/MainWindow.axaml`
  - Code: `VulcansTrace.Linux.Avalonia/MainWindow.axaml.cs`
- Trace Map / Incident Graph: interactive attack-chain visualization on the timeline canvas. Directed correlation edges (escalation, temporal sequence, same-host) are drawn between related findings. Click-to-highlight with BFS chain walking, narrative panel, host-based grouping toggle, and performance guardrail (>100 edges suppresses canvas rendering).
  - Code: `VulcansTrace.Linux.Engine/TraceMapCorrelator.cs`
  - Code: `VulcansTrace.Linux.Avalonia/ViewModels/TimelineViewModel.cs`
  - Code: `VulcansTrace.Linux.Avalonia/MainWindow.axaml.cs`
  - Code: `VulcansTrace.Linux.Evidence/Formatters/TraceMapMarkdownFormatter.cs`
  - Code: `VulcansTrace.Linux.Evidence/Formatters/TraceMapJsonFormatter.cs`
- Incident Story Mode: dedicated Avalonia tab that turns findings into a flowing attack narrative with time-ordered beats, likely chain summary, recommended responses, and one-click markdown copy. The same narrative is exported as `incident-story.md` in the signed evidence ZIP.
  - Code: `VulcansTrace.Linux.Evidence/Formatters/IncidentStoryFormatter.cs`
  - Code: `VulcansTrace.Linux.Avalonia/ViewModels/IncidentStoryViewModel.cs`
  - Code: `VulcansTrace.Linux.Avalonia/Views/IncidentStoryView.axaml`
  - Code: `VulcansTrace.Linux.Avalonia/MainWindow.axaml`
- Dialogs: moved from FluentAvalonia ContentDialog to a native Avalonia Window.
  - Code: `VulcansTrace.Linux.Avalonia/Services/AvaloniaDialogService.cs`

### Dependencies
- Removed FluentAvalonia UI dependency.
- Added `Avalonia.Controls.DataGrid` (11.3.11) for the grid view.
  - Code: `VulcansTrace.Linux.Avalonia/VulcansTrace.Linux.Avalonia.csproj`

### Tests and fixtures
- Updated tests to match the refined detectors and avoid time-window flakiness.
  - Code: `VulcansTrace.Linux.Tests/Detectors/Linux/FlagAnomalyDetectorTests.cs`
  - Code: `VulcansTrace.Linux.Tests/Detectors/PrivilegeEscalationDetectorTests.cs`
  - Code: `VulcansTrace.Linux.Tests/Integration/RealWorldAttackScenarioTests.cs`
  - Code: `VulcansTrace.Linux.Tests/Integration/SentryAnalyzerTests.cs`
- Trace Map tests: correlator confidence levels, BFS chain walking, edge suppression threshold, narrative generation, deterministic edge IDs, JSON/Markdown formatter coverage, and E2E evidence bundle inclusion.
  - Code: `VulcansTrace.Linux.Tests/Engine/TraceMapCorrelatorTests.cs`
  - Code: `VulcansTrace.Linux.Tests/Avalonia/TimelineViewModelTraceMapTests.cs`
  - Code: `VulcansTrace.Linux.Tests/Evidence/TraceMapJsonFormatterTests.cs`
  - Code: `VulcansTrace.Linux.Tests/Evidence/TraceMapMarkdownFormatterTests.cs`
  - Code: `VulcansTrace.Linux.Tests/Evidence/IncidentStoryFormatterTests.cs`
  - Code: `VulcansTrace.Linux.Tests/Evidence/EvidenceBuilderTests.cs`
- Expanded `iptables-attack.log` to reliably trigger visible PortScan findings
  at Medium and High intensity. Low still evaluates the scan, but standalone
  PortScan findings are hidden by the High/Critical visibility filter unless
  correlation escalates them.
  - Fixture: `VulcansTrace.Linux.Tests/Data/Real/Samples/iptables-attack.log`

### Security Agent — File Permission Auditing
- Added `FilePermissionScanner` that uses `stat` to read permission bits, ownership, and existence of sensitive files and directories (`/etc/shadow`, `/etc/passwd`, `/etc/ssh/ssh_host_*_key`, `/root/.ssh`, `/etc/cron.*`, `/var/spool/cron`, `/etc/crontab`, and user SSH directories under `/home`).
- Added 7 file permission rules (`FILE-001` through `FILE-007`) with dual-layer CIS compliance mappings:
  - `FILE-001` — `/etc/shadow` should be `640/600`, root-owned (CIS 6.1)
  - `FILE-002` — `/etc/passwd` should be `644`, root-owned (CIS 6.1)
  - `FILE-003` — SSH host private keys should be `600`, root-owned (CIS 5.2)
  - `FILE-004` — `/root/.ssh` should be `700`; `authorized_keys` should be `600` (CIS 5.2)
  - `FILE-005` — Cron directories should not be world-writable (CIS 6.1)
  - `FILE-006` — `/etc/crontab` should be `644/600`, root-owned (CIS 6.1)
  - `FILE-007` — User SSH directories and `authorized_keys` should be tightly restricted (CIS 5.2)
- Added `AgentIntent.FilePermissionCheck` and `QueryParser` keywords so users can ask "check file permissions".
- Added `filepermission.md` explanation template with remediation steps for all file permission rules.
- Code: `VulcansTrace.Linux.Agent/Scanners/FilePermissionScanner.cs`, `VulcansTrace.Linux.Agent/Rules/SecurityRules/FilePermissionRules.cs`, `VulcansTrace.Linux.Agent/Explanations/Templates/filepermission.md`, `VulcansTrace.Linux.Agent/Query/QueryParser.cs`

### Security Agent — Interactive Remediation And Guided Sessions
- Added `AgentIntent.FixFinding` and `HandleFixFindingAsync` for single-finding remediation previews.
- `QueryParser` recognizes `fix FW-001` / `resolve SSH-003` for single-finding remediation previews and `remediate PORT-002` for persisted guided remediation sessions (`fix ` requires a trailing space so `what should i fix` still routes to `PrioritizeRemediation`).
- `HandleFixFindingAsync` builds a single-section `RemediationPlan`, runs `RemediationPlanValidator` to block risky commands without rollback guidance, and returns an interactive remediation card.
- UI renders preconditions, backup commands, apply commands, rollback commands, and verification commands with the same safety and structural badges used for verification commands.
- Added 10 new tests covering intent parsing, target reference extraction, and all `HandleFixFindingAsync` code paths (no context, no reference, unknown reference, success, validation failure).
- Code: `VulcansTrace.Linux.Agent/Query/AgentIntent.cs`, `VulcansTrace.Linux.Agent/Query/QueryParser.cs`, `VulcansTrace.Linux.Agent/SecurityAgent.cs`, `VulcansTrace.Linux.Avalonia/ViewModels/AgentViewModel.cs`, `VulcansTrace.Linux.Avalonia/AgentView.axaml`, `VulcansTrace.Linux.Tests/Agent/QueryParserTests.cs`, `VulcansTrace.Linux.Tests/Agent/SecurityAgentTests.cs`

### Security Agent — Offline Threat Intel Correlation (STIX/MISP Import)
- Added `IThreatIntelStore` abstraction with `InMemoryThreatIntelStore` and `JsonFileThreatIntelStore` (persists to `~/.config/VulcansTrace/threat-intel.json`).
- Added `StixParser` for STIX 2.1 bundle JSON and `MispParser` for MISP event JSON, extracting IPv4, IPv6, domain, URL, port, and file hash IOCs.
- Added `ThreatIntelDetector` (Engine) that correlates firewall logs against imported IP and port IOCs.
- Added `FileHashScanner` that hashes security-interesting files (SUID/SGID, world-writable, unowned, cron scripts) via `sha256sum`/`md5sum`/`sha1sum`.
- Added 3 threat intel rules (`TI-001` through `TI-003`) correlating active connections, open ports, and file hashes against imported IOCs.
- Added CLI `threat-intel import --file <path> [--format stix|misp|auto]`, `status`, and `clear` commands.
- Added Avalonia UI **Import Threat Intel** button with file picker and format auto-detection.
- Added `AgentIntent.ThreatIntelCheck`, QueryParser keywords, `FilterRulesByIntent` case, and `GetIntentDisplayName` mapping.
- Code: `VulcansTrace.Linux.Agent/ThreatIntel/*`, `VulcansTrace.Linux.Engine/Detectors/ThreatIntelDetector.cs`, `VulcansTrace.Linux.Agent/Scanners/FileHashScanner.cs`, `VulcansTrace.Linux.Agent/Rules/SecurityRules/ThreatIntel/*`, `VulcansTrace.Linux.Cli/Program.cs`, `VulcansTrace.Linux.Avalonia/ViewModels/AgentViewModel.cs`

### Security Agent — Batch Auto-Fix (CLI)
- Added `--auto-fix`, `--dry-run`, `--yes`, `--allow-restart`, and `--allow-packages` flags to the CLI `audit` command.
- `AutoFixPolicy` defines which `CommandSafety` levels are permitted for automatic execution (`Conservative`, `Standard`, `Aggressive` presets).
- `RemediationPlanBuilder` constructs a plan from all findings; `RemediationPlanValidator` blocks sections lacking rollback guidance.
- `RemediationExecutor` orchestrates backup → apply → verify sequentially, with automatic rollback on apply failure. Cancellation is checked before every command via `ExecuteCommandAsync`.
- `ProcessRunner` feeds commands to bash via stdin instead of `-c "..."` to eliminate shell escaping vulnerabilities (newlines, quotes, backticks, `$()`).
- `CommandSafetyClassifier` labels every extracted command by safety impact and structural patterns (sudo, chains, pipes, redirects, download-and-execute).
- Exit codes combined: audit result (`0` or `2`) and auto-fix result (`0` or `3`) use `Math.Max`, so critical findings are never masked by successful auto-fix.
- Scheduled audits (`schedule run`) also support `--auto-fix` flags when invoked manually.
- Auto-fix services (`IProcessRunner`, `RemediationExecutor`, `RemediationPlanBuilder`) are wired into `AgentFactory` and `AgentServices` for centralized composition and testability.
- 30+ new tests covering policy behavior, executor edge cases, rollback behavior, cancellation mid-execution, process runner timeout, console formatter output, and CLI flow integration.
- Code: `VulcansTrace.Linux.Agent/Remediation/*.cs`, `VulcansTrace.Linux.Cli/Program.cs`, `VulcansTrace.Linux.Agent/AgentFactory.cs`, `VulcansTrace.Linux.Tests/Agent/Remediation/*`, `VulcansTrace.Linux.Tests/Cli/AutoFixCliTests.cs`

### Security Agent — Kernel and System Hardening
- Added `KernelHardeningScanner` that reads 9 sysctl values directly from `/proc/sys/` (fast, no shell), with `sysctl -a` fallback for missing values, and checks Secure Boot via `mokutil --sb-state` with EFI variable fallback.
- Added `KernelParameters` record to `ScanData` with typed fields: `RandomizeVaSpace`, `IpForwardIpv4/Ipv6`, `AcceptRedirectsIpv4/Ipv6`, `AcceptSourceRouteIpv4`, `ModulesDisabled`, `SecureBootEnabled`, `KptrRestrict`, `DmesgRestrict`.
- Added 7 kernel hardening rules (`KERN-001` through `KERN-007`) with dual-layer CIS compliance mappings:
  - `KERN-001` — ASLR fully enabled (`kernel.randomize_va_space >= 2`) (CIS 1.5)
  - `KERN-002` — IP forwarding disabled (IPv4 + IPv6) (CIS 3.1)
  - `KERN-003` — ICMP redirects disabled (IPv4 + IPv6) (CIS 3.1)
  - `KERN-004` — Source routed packets rejected (CIS 3.1)
  - `KERN-005` — Kernel module loading restricted (`kernel.modules_disabled != 0`); role-aware severity: High on Server, Medium on Workstation (CIS 1.4)
  - `KERN-006` — Secure Boot enabled; returns `NotApplicable` on BIOS/legacy systems where Secure Boot is unavailable (CIS 1.4)
  - `KERN-007` — Kernel pointer and dmesg exposure restricted (`kptr_restrict >= 1`, `dmesg_restrict == 1`) (CIS 1.5)
- Added `AgentIntent.KernelCheck` and `QueryParser` keywords so users can ask "check my kernel hardening".
- Added `kernel.md` explanation template with remediation steps for all kernel hardening rules.
- Added `RuleStatus.NotApplicable` for hardware-dependent checks that do not apply to the current system (e.g., Secure Boot on BIOS). `BuildSummary` reports not-applicable counts in the audit summary.
- Code: `VulcansTrace.Linux.Agent/Scanners/KernelHardeningScanner.cs`, `VulcansTrace.Linux.Agent/Rules/SecurityRules/KernelHardeningRules.cs`, `VulcansTrace.Linux.Agent/Explanations/Templates/kernel.md`, `VulcansTrace.Linux.Agent/Query/QueryParser.cs`, `VulcansTrace.Linux.Agent/SecurityAgent.cs`

### Security Agent — User & Account Auditing
- Added `UserAccountScanner` that reads `/etc/passwd`, `/etc/shadow`, `/etc/login.defs`, PAM password-stack configs (`common-password`, `system-auth`, `password-auth`, `/etc/security/pwquality.conf`), PAM auth-stack configs (`common-auth`, `/etc/pam.d/sshd`), and `/etc/security/faillock.conf`. Note: only local files are scanned; LDAP/NIS/AD users are not covered.
- Added `UserAccount`, `ShadowEntry`, `LoginDefs`, and `PamConfig` records to `ScanData`.
- Added 10 user account rules (`USER-001` through `USER-010`) with dual-layer CIS compliance mappings:
  - `USER-001` — Only root should have UID 0 (CIS 6.2)
  - `USER-002` — Empty or unset password hashes flagged; locked interactive accounts flagged at lower severity (CIS 5.4)
  - `USER-003` — Password aging enforces `PASS_MAX_DAYS <= 90`, `PASS_MIN_DAYS >= 1`, `PASS_WARN_AGE >= 7`, plus per-user shadow checks (CIS 5.4)
  - `USER-004` — PAM password-stack must include a complexity module (`pam_pwquality.so`, `pam_cracklib.so`, or `pam_passwdqc.so`) (CIS 5.4)
  - `USER-005` — Inactive or locked interactive accounts (UID >= 1000) with expired expiry dates flagged (CIS 6.2)
  - `USER-006` — Each UID should be unique (CIS 6.2)
  - `USER-007` — Regular interactive accounts should have an existing home directory (CIS 6.2)
  - `USER-008` — PAM faillock must be configured in every auth stack (`preauth` + `authfail`) with a readable `faillock.conf` (CIS 5.3)
  - `USER-009` — PAM password quality must enforce `minlen >= 14`, `minclass >= 3`, and credit requirements (`dcredit`, `ucredit`, `lcredit`, `ocredit`) (CIS 5.4)
  - `USER-010` — PAM auth stack must place `required`/`requisite`/`binding` or bracketed controls before any `sufficient` module in every file (CIS 5.3)
- `EmptyPasswordRule` returns `NotApplicable` when `/etc/shadow` is unreadable (non-root), matching `KERN-006` behavior.
- `PamPasswordComplexityRule` only inspects PAM lines in the `password` management stack.
- `PamAuthRequiredRule` evaluates auth stack ordering per-file using `PamConfig.RawLinesByFile`; fails if any single file has `sufficient` before mandatory controls.
- `MissingHomeDirectoryRule` uses pre-collected `HomeDirectoryExists` from the scanner instead of calling `Directory.Exists()` at evaluation time.
- Added `AgentIntent.UserAccountCheck` and `QueryParser` keywords so users can ask "check my user accounts".
- Added `useraccount.md` explanation template with remediation steps for all user account rules.
- Code: `VulcansTrace.Linux.Agent/Scanners/UserAccountScanner.cs`, `VulcansTrace.Linux.Agent/Rules/SecurityRules/UserAccountRules.cs`, `VulcansTrace.Linux.Agent/Explanations/Templates/useraccount.md`, `VulcansTrace.Linux.Agent/Query/QueryParser.cs`, `VulcansTrace.Linux.Agent/SecurityAgent.cs`

### Security Agent — Filesystem Auditing
- Added `FilesystemAuditScanner` that runs targeted `find` commands to discover world-writable files, SUID/SGID binaries, unowned files, world-writable directories without sticky bit, and `/tmp` mount options.
- Added 5 filesystem audit rules (`FSYS-001` through `FSYS-005`) with dual-layer CIS compliance mappings:
  - `FSYS-001` — World-writable files outside expected temporary paths (CIS 6.1.9)
  - `FSYS-002` — Unexpected SUID/SGID binaries outside the known-good full-path whitelist (CIS 6.1.12)
  - `FSYS-003` — Unowned files (no valid user or group) (CIS 6.1.11)
  - `FSYS-004` — World-writable directories without sticky bit (CIS 6.1.10)
  - `FSYS-005` — `/tmp` should be a separate mount with `noexec`, `nosuid`, and `nodev` (CIS 1.1.2)
- `AgentIntent.FilesystemAuditCheck` and `QueryParser` keywords so users can ask "check my filesystem" or "any SUID binaries?".
- Added `FilesystemAuditEntry` record to `ScanData` with `Path`, `Mode`, `Owner`, `Group`, and `AuditCategory`.
- Added `TmpMountOptions` and `TmpMountTarget` to `ScanData` for `/tmp` mount analysis.
- SUID whitelist uses **full paths** (not filenames) to prevent bypass by naming a backdoor after a whitelisted binary.
- Fingerprints are stable: rules sort findings by path and use the first path only in `Target`, with count in `Variables`.
- Added `filesystemaudit.md` explanation template with remediation steps for all filesystem audit rules.
- Code: `VulcansTrace.Linux.Agent/Scanners/FilesystemAuditScanner.cs`, `VulcansTrace.Linux.Agent/Rules/SecurityRules/FilesystemAuditRules.cs`, `VulcansTrace.Linux.Agent/Explanations/Templates/filesystemaudit.md`, `VulcansTrace.Linux.Agent/Scanners/ScanData.cs`, `VulcansTrace.Linux.Agent/Query/QueryParser.cs`

### Security Agent — Logging & Auditing
- Added `LoggingAuditScanner` that checks rsyslog and journald service status, reads auditd rules via `auditctl -l` with fallback to `/etc/audit/audit.rules`, checks logrotate configuration, and detects central log forwarding via rsyslog (`@`/`@@` targets) and journald (`ForwardToSyslog=yes`).
- Added `LoggingAuditConfig` record to `ScanData` with typed fields: `RsyslogActive`, `JournaldActive`, `AuditdActive`, `AuditdRulesConfigured`, `LogRotationConfigured`, `CentralForwardingConfigured`, `AuditdRules`, `ForwardingTargets`, `ReadWarning`.
- Added 7 logging/audit rules (`LOG-001` through `LOG-007`) with dual-layer CIS compliance mappings:
  - `LOG-001` — At least one system logging service (rsyslog or journald) should be active (CIS 8.1)
  - `LOG-002` — auditd should be installed and active (CIS 8.2)
  - `LOG-003` — auditd should have active rules monitoring key security events (CIS 8.2)
  - `LOG-004` — Log rotation should be configured via logrotate (CIS 8.3)
  - `LOG-005` — Central log forwarding should be configured (rsyslog remote or journald ForwardToSyslog); exempt on Workstation, DevMachine, LabBox, and Router (CIS 8.4)
  - `LOG-006` — auditd should monitor privilege escalation syscalls (`setuid`, `setgid`, etc.) (CIS 8.2)
  - `LOG-007` — Central forwarding should use TCP (`@@` target) rather than UDP (`@`) for reliability (CIS 8.4)
- `LOG-003` and `LOG-006` return `NotApplicable` when `ReadWarning` is set (partial scanner failure such as permission denied) so they do not produce false negatives on incomplete data.
- `IsForwardingTarget` filters rsyslog control directives (`@include`, `@version`, `@moduleLoad`, etc.) to prevent false positives.
- `IsActualAuditdRule` distinguishes real audit rules (`-w`, `-a`, `-A`) from control directives (`-D`, `-b`, `-f`, etc.).
- `CheckCentralForwarding` uses `HashSet<string>` for deduplication and supports both rsyslog config files and journald.conf.
- Added `AgentIntent.LoggingAuditCheck` and `QueryParser` keywords (`logging`, `log`, `rsyslog`, `journald`, `auditd`, `logrotate`, `forwarding`, `syslog`) so users can ask "check my logging".
- Added `loggingaudit.md` explanation template with remediation steps for all logging/audit rules.
- Code: `VulcansTrace.Linux.Agent/Scanners/LoggingAuditScanner.cs`, `VulcansTrace.Linux.Agent/Rules/SecurityRules/LoggingAuditRules.cs`, `VulcansTrace.Linux.Agent/Explanations/Templates/loggingaudit.md`, `VulcansTrace.Linux.Agent/Query/QueryParser.cs`, `VulcansTrace.Linux.Agent/SecurityAgent.cs`

### Security Agent — Cron Job Auditing
- Added `CronJobScanner` that reads and parses system crontabs (`/etc/crontab`, `/etc/cron.d/*`), user crontabs (`/var/spool/cron/crontabs/*`, `/var/spool/cron/*` for RHEL/CentOS/Fedora), and cron script directories (`cron.daily`, `cron.hourly`, `cron.weekly`, `cron.monthly`). Uses `stat` for script permissions.
- Added `CronJobEntry` record to `ScanData` with `SourceFile`, `Schedule`, `Command`, `RunAsUser`, `IsScript`, `ScriptPermissions`, `ScriptOwner`, and `ScriptGroup`.
- Added 3 cron job rules (`CRON-001` through `CRON-003`) with dual-layer CIS compliance mappings:
  - `CRON-001` — Suspicious cron commands (reverse shells, network downloaders, temp paths, encoded payloads). Uses word-boundary-aware pattern matching to reduce false positives (CIS 6.1)
  - `CRON-002` — Cron scripts should not be world-writable; setuid/setgid bits escalated to `Critical` severity (CIS 6.1)
  - `CRON-003` — Root cron jobs should not reference non-root user directories (`/home/` or `~username`) (CIS 6.2)
- All cron rules return `NotApplicable` when no cron data is available.
- `AgentIntent.CronJobCheck` and `QueryParser` keywords (`cron`, `crontab`, `scheduled job`, `cron job`) so users can ask "check my cron jobs".
- Added `cron.md` explanation template with remediation steps for all cron job rules.
- 30+ new tests covering scanner parsing, word-boundary matching, setuid detection, tilde-user path detection, multiple-match reporting, and NotApplicable behavior.
- Code: `VulcansTrace.Linux.Agent/Scanners/CronJobScanner.cs`, `VulcansTrace.Linux.Agent/Rules/SecurityRules/CronJobRules.cs`, `VulcansTrace.Linux.Agent/Explanations/Templates/cron.md`, `VulcansTrace.Linux.Agent/Query/QueryParser.cs`, `VulcansTrace.Linux.Agent/SecurityAgent.cs`, `VulcansTrace.Linux.Agent/Query/AgentIntent.cs`

### Security Agent — Package Vulnerability Scanning
- Added `PackageVulnerabilityScanner` that enumerates installed packages via `dpkg-query`, detects pending security updates via `apt list --upgradeable` and `apt-cache policy` (classifying updates from security repositories), optionally enriches findings with specific CVE IDs when `debsecan` is installed, and checks `unattended-upgrades` configuration.
- Added `InstalledPackage`, `VulnerablePackage`, and `PackageVulnerabilityStatus` records to `ScanData` with typed fields: `Name`, `Version`, `Architecture`, `InstalledVersion`, `AvailableVersion`, `IsSecurityUpdate`, `CveIds`, `Source`, `PackagesReadable`, `UnattendedUpgradesConfigured`, `UnattendedUpgradesEnabled`, `CveDataAvailable`.
- Added 3 package vulnerability rules (`PKG-VULN-001` through `PKG-VULN-003`) with dual-layer CIS compliance mappings:
  - `PKG-VULN-001` — Pending security updates should be applied promptly; severity escalates to `Critical` when 5+ security updates are pending (CIS 1.9)
  - `PKG-VULN-002` — Automatic security updates via `unattended-upgrades` should be configured (CIS 1.9)
  - `PKG-VULN-003` — Known CVEs affecting installed packages should be tracked and patched; returns `NotApplicable` when CVE enrichment data (debsecan) is unavailable, preventing false confidence (no direct CIS mapping)
- All package vulnerability rules return `NotApplicable` when package data is unreadable (dpkg-query failed or permission denied), matching the behavior of `LoggingAuditRules` and `CronJobRules`.
- `AgentIntent.PackageVulnerabilityCheck` and `QueryParser` keywords (`package`, `vulnerability`, `cve`, `security update`, `apt`, `upgradeable`, `patch`) so users can ask "check package vulnerabilities".
- Added `packagevulnerability.md` explanation template with remediation steps for all package vulnerability rules.
- Scanner handles edge cases robustly: OCE during optional debsecan enrichment does not discard core dpkg/apt data; empty dpkg-query output on success is distinguished from command failure; per-package `apt-cache policy` failures emit warnings; `CheckUnattendedUpgrades` uses a simple line-scan parser instead of fragile block-state tracking.
- CVEs for packages without upgradeable versions in configured repos are still reported (with `Source = "debsecan (fix may require repository reconfiguration)"`), preventing silent data loss.
- Added `FindingCategories.PackageVulnerability` constant for consistency with other rule families.
- 20+ new tests covering scanner parser fixtures (dpkg, apt, apt-cache policy, debsecan), rule behavior (NotApplicable on missing data, severity escalation, CVE availability gating), and query parser keyword matching.
- Code: `VulcansTrace.Linux.Agent/Scanners/PackageVulnerabilityScanner.cs`, `VulcansTrace.Linux.Agent/Rules/SecurityRules/PackageVulnerabilityRules.cs`, `VulcansTrace.Linux.Agent/Explanations/Templates/packagevulnerability.md`, `VulcansTrace.Linux.Agent/Query/QueryParser.cs`, `VulcansTrace.Linux.Agent/Query/AgentIntent.cs`, `VulcansTrace.Linux.Agent/SecurityAgent.cs`, `VulcansTrace.Linux.Core/FindingCategories.cs`

### Security Agent — SSH Daemon Auditing
- Added `SshConfigScanner` that reads `sshd -T` output (with fallback to `/etc/ssh/sshd_config` plus `Include` directives).
- Added 8 SSH hardening rules (`SSH-001` through `SSH-008`) with dual-layer CIS compliance mappings:
  - `SSH-001` — `PermitRootLogin` should be disabled or `prohibit-password` (CIS 5.4)
  - `SSH-002` — `PasswordAuthentication` should be disabled (CIS 6.3)
  - `SSH-003` — `MaxAuthTries` should be 4 or lower (CIS 6.3)
  - `SSH-004` — SSH Protocol 1 should not be enabled (CIS 4.8)
  - `SSH-005` — `PermitEmptyPasswords` should be disabled (CIS 5.2)
  - `SSH-006` — `PubkeyAuthentication` should be enabled (CIS 6.3)
  - `SSH-007` — `X11Forwarding` should be disabled on servers (CIS 4.8)
  - `SSH-008` — `UsePAM` should be enabled to enforce local PAM policies (CIS 5.2)
- `SshX11ForwardingRule` is role-aware: returns `Pass` on `Workstation` where X11 forwarding may be intentional.
- Added `AgentIntent.SshCheck` and `QueryParser` keywords so users can ask "check my SSH".
- Added `ssh.md` explanation template with remediation steps for all SSH rules.
- Code: `VulcansTrace.Linux.Agent/Scanners/SshConfigScanner.cs`, `VulcansTrace.Linux.Agent/Rules/SecurityRules/SshRules.cs`, `VulcansTrace.Linux.Agent/Explanations/Templates/ssh.md`

### Security Agent — Container & Kubernetes Security Scanner
- Added `ContainerScanner` that scans local container runtime state via `docker ps` + `docker inspect` (with `crictl` fallback), detecting running containers, privileged mode, `latest` tags, Docker socket exposure/mounts, known risky base-image hints from local image metadata, and containerd namespace isolation. Per-element try/catch in parsers emits warnings instead of silently swallowing malformed entries.
- Added `KubernetesScanner` that scans Kubernetes pods via `kubectl get pods --all-namespaces -o json` when a kubeconfig is present. Supports the `$KUBECONFIG` environment variable and uses the configured cluster context. Detects privileged containers, `hostNetwork`/`hostPID`/`hostIPC` sharing, root containers, and missing security context hardening (`allowPrivilegeEscalation: false`, `readOnlyRootFilesystem`, dropped capabilities, confined seccomp profile). Pod-level `securityContext` is inherited by containers with container-level overrides respected.
- Added 5 container security rules (`CTR-001` through `CTR-005`) with dual-layer CIS compliance mappings:
  - `CTR-001` — Privileged containers should not be running (CIS Docker Benchmark 5.4)
  - `CTR-002` — Container images should not use the `latest` tag (CIS Docker Benchmark 4.1)
  - `CTR-003` — Docker socket should not be exposed on the host or mounted into containers (CIS Docker Benchmark 5.25)
  - `CTR-004` — Containerd should use explicit namespaces rather than only the default (CIS Containerd Benchmark 1.1)
  - `CTR-005` — Container images should not use known risky base-image hints (CIS Docker Benchmark 4.1)
- Added 4 Kubernetes security rules (`K8S-001` through `K8S-004`) with dual-layer CIS compliance mappings:
  - `K8S-001` — Pods should not run privileged containers (CIS Kubernetes Benchmark 5.2.1)
  - `K8S-002` — Pods should not use `hostNetwork`, `hostPID`, or `hostIPC` (CIS Kubernetes Benchmark 5.2.4)
  - `K8S-003` — Containers should run as non-root (CIS Kubernetes Benchmark 5.2.6)
  - `K8S-004` — Containers should have hardened security contexts, including disabled privilege escalation and confined seccomp (CIS Kubernetes Benchmark 5.2.7)
- Added `ContainerRuntimeInfo`, `ContainerInfo`, `KubernetesPodInfo`, and `K8sContainerInfo` records to `ScanData` / `ScanDataBuilder`.
- Added `FindingCategories.Container` and `FindingCategories.Kubernetes` constants.
- Added `AgentIntent.ContainerCheck` and `AgentIntent.KubernetesCheck` with `QueryParser` keywords (`container`, `docker`, `kubernetes`, `k8s`, `pod`, `pods`).
- Added container/kubernetes intent filtering in `RuleEvaluationService.FilterRulesByIntent`.
- Added follow-up intent mapping in `AgentFollowUpService.InferIntentFromCategory` for `ContainerCheck` and `KubernetesCheck`.
- Added result composer labels (`Container check`, `Kubernetes check`) in `AgentResultComposer.BuildSummary`.
- Added `container.md` and `kubernetes.md` explanation templates with remediation steps.
- Scanner failures (missing docker/crictl/ctr/kubectl, permission denied, malformed JSON) are reported as warnings without crashing the agent.
- All container and Kubernetes rules return `Pass` when the respective runtime is unavailable, preventing false positives on non-containerized hosts.
- 20+ new tests covering scanner parser fixtures (docker ps, docker inspect JSON, crictl JSON, ctr namespace, kubectl pods JSON), rule behavior (privileged, latest tag, socket exposure/mount, known risky base hints, namespace defaults, pod security context inheritance, root detection, capability/seccomp checks), intent parsing, UI audit-state routing, and `RuleCatalogTests` count update.
  - Code: `VulcansTrace.Linux.Agent/Scanners/ContainerScanner.cs`, `VulcansTrace.Linux.Agent/Scanners/KubernetesScanner.cs`, `VulcansTrace.Linux.Agent/Rules/SecurityRules/ContainerRules.cs`, `VulcansTrace.Linux.Agent/Rules/SecurityRules/KubernetesRules.cs`, `VulcansTrace.Linux.Agent/Explanations/Templates/container.md`, `VulcansTrace.Linux.Agent/Explanations/Templates/kubernetes.md`, `VulcansTrace.Linux.Agent/Query/QueryParser.cs`, `VulcansTrace.Linux.Agent/Query/AgentIntent.cs`, `VulcansTrace.Linux.Agent/SecurityAgent.cs`, `VulcansTrace.Linux.Core/FindingCategories.cs`

### Security Agent — Runtime Process Threat Hunting
- Added `ProcessRuntimeScanner` that enumerates all numeric directories in `/proc/`, reads six files per process (`status`, `comm`, `exe` via `readlink`, `cmdline`, `maps`, `environ`) with bounded concurrency (`SemaphoreSlim(50)`), per-file fault isolation (`TryReadAsync`), and read loops into bounded `MemoryStream` to handle partial procfs reads.
- Added `ProcessRuntimeEntry` record with `Pid`, `Name`, `ExePath`, `Cmdline`, `Ppid`, `Uid`, `MemoryMaps`, `Environment`, `StatusDuplicateFieldCount`, `CmdlineTruncated`, `EnvironTruncated`, and `MapsTruncated`.
- Added 6 process runtime rules (`PROC-001` through `PROC-006`) with MITRE ATT&CK mappings:
  - `PROC-001` — RWX memory mappings indicating process injection or shellcode (Critical, T1055/T1620)
  - `PROC-002` — `LD_PRELOAD` / `LD_AUDIT` dynamic linker hijacking (High, T1574.006)
  - `PROC-003` — Execution from deleted binaries or temporary paths (`/tmp`, `/var/tmp`, `/dev/shm`) (High, T1036/T1105)
  - `PROC-004` — Orphaned processes with anomalous names running under init (Medium, T1036)
  - `PROC-005` — Suspicious parent-child relationships (High, T1059); tracks `missingParentCount` and `totalChecked` metadata
  - `PROC-006` — Interpreter processes with RWX mappings, highlighting python/perl/ruby/php in-memory payload execution (Critical, T1055/T1620/T1059)
- Defensive parsing hardening:
  - `ReadStatusAsync` guards against duplicate headers with first-value-wins and `DuplicateFieldCount`
  - `ReadProcFileAsync` returns `(byte[] Data, bool Truncated)` with a 1-byte peek-read at cap boundary
  - PROC-001, PROC-002, and PROC-006 include truncation metadata (`mapsTruncated`, `environTruncated`) on both Pass and Fail
  - PROC-001, PROC-002, PROC-003, and PROC-006 distinguish unreadable `/proc` evidence from empty evidence, returning `NotApplicable` when required data is entirely unreadable and surfacing unreadable-count metadata for partial visibility
- PROC-005 uses exact-match / `StartsWith` parent names (not `Contains`) to avoid `apachectl` false positives; `IsInterpreter` detects versioned interpreters (`python3.11`, `php8.1`, `ruby3.2`, `perl5.34`) via digit-prefix checks.
- `AgentIntent.ProcessRuntimeCheck` and `QueryParser` keywords (`process`, `processes`, `running process`, `runtime process`, `process runtime`) so users can ask "check my processes".
- Added `processruntime.md` explanation template with remediation steps for all 6 rules.
- Added `ProcessRuntimeMitreMappings` static technique catalog inside `ProcessRuntimeRules.cs`.
- 50+ tests covering `ParseMapLine`, `IsAnomalousName`, `IsSuspiciousPair`, all 6 rules across pass/fail/NotApplicable, missing-parent metadata, truncation metadata, unreadable-evidence semantics, and interpreter RWX detection.
- Code: `VulcansTrace.Linux.Agent/Scanners/ProcessRuntimeScanner.cs`, `VulcansTrace.Linux.Agent/Scanners/ProcessRuntimeEntry.cs`, `VulcansTrace.Linux.Agent/Rules/SecurityRules/ProcessRuntimeRules.cs`, `VulcansTrace.Linux.Agent/Explanations/Templates/processruntime.md`, `VulcansTrace.Linux.Tests/Agent/ProcessRuntimeScannerTests.cs`, `VulcansTrace.Linux.Tests/Agent/ProcessRuntimeRulesTests.cs`

### Security Agent — CIS Benchmark Mapping
- All 81 agent rules now carry dual-layer CIS compliance mappings:
  - **CIS Controls v8** (organizational): e.g., `CIS 4.5`, `CIS 5.4`, `CIS 6.3`
  - **CIS Ubuntu 24.04 LTS Benchmark** (technical): e.g., `5.2.7 Ensure SSH root login is disabled`
  - `CisBenchmarkMapping` record extended with optional `BenchmarkReference` field
  - Mappings flow through full audits, single-rule explanations, crashes, and policy-disabled results
  - Evidence exports preserve mappings in CSV, HTML, Markdown, JSON, and STIX formats
  - HTML and Markdown compliance-context deduplication changed from `ControlId`-only grouping to `Distinct()` so unique rationale per rule is preserved
  - Code: `VulcansTrace.Linux.Core/CisBenchmarkMapping.cs`, `VulcansTrace.Linux.Agent/Rules/SecurityRules/*.cs`, `VulcansTrace.Linux.Evidence/Formatters/*.cs`

### Recurring Audit Scheduling
- Headless CLI (`VulcansTrace.Linux.Cli`) with `audit` and `schedule` subcommands for running audits and managing recurring schedules without the desktop UI.
  - Commands: `list`, `add`, `edit`, `delete`, `enable`, `disable`, `run`, `install-cron`, `uninstall-cron`.
  - Exit codes: 0 (success), 1 (error), 2 (success with critical findings), 3 (auto-fix executed but some remediation commands failed).
  - Code: `VulcansTrace.Linux.Cli/Program.cs`
- GUI Schedule Editor (`ScheduleView`) in the Avalonia UI with a DataGrid, Add/Edit/Delete/Run Now/Install Cron actions, and cron status indicators.
  - Code: `VulcansTrace.Linux.Avalonia/Views/ScheduleView.axaml`, `VulcansTrace.Linux.Avalonia/ViewModels/ScheduleViewModel.cs`, `ScheduleEditWindow.axaml`
- System crontab integration (`CrontabManager`) reads and writes the user crontab, using a unique marker prefix (`# VT-SCH-7a3f9e2d schedule-id=`) to avoid collision with non-VulcansTrace entries.
  - Code: `VulcansTrace.Linux.Agent/Scheduling/CrontabManager.cs`
- Cron expression validation (`CronExpressionValidator`) ensures 5-field syntax before saving.
  - Code: `VulcansTrace.Linux.Agent/Scheduling/CronExpressionValidator.cs`
- Schedule persistence via `JsonFileScheduleStore` (atomic temp-file writes to `~/.config/VulcansTrace/schedules.json`) and `InMemoryScheduleStore` fallback.
  - Code: `VulcansTrace.Linux.Agent/Scheduling/JsonFileScheduleStore.cs`, `InMemoryScheduleStore.cs`
- Fingerprint-aware new-critical-only diffing compares current audit critical findings against the previous `AuditHistoryEntry` and only notifies when new critical fingerprints appear. Pre-fingerprint history entries are handled gracefully to avoid upgrade-storm notifications.
  - Code: `VulcansTrace.Linux.Cli/Program.cs`, `VulcansTrace.Linux.Avalonia/ViewModels/ScheduleViewModel.cs`
- Machine role picker dropdown in the Avalonia UI allows hot-swapping roles without code changes.
  - Code: `VulcansTrace.Linux.Avalonia/ViewModels/MainViewModel.cs`, `AgentViewModel.cs`

### Security Agent — Remediation Session Notes + Evidence Attachments
- Added `SessionNote` record to `RemediationSession` with `Text`, `CreatedAtUtc`, optional `RuleId`, and `EvidenceLinks`.
- Added `SessionNoteAdded` and `StepNoteAdded` to `RemediationSessionEventType` for immutable timeline recording.
- Added `GuidedRemediationService.AddSessionNote` and `AddStepNote` — append-only, validates the session exists, guards against null/empty rule IDs and unknown steps, and returns concise confirmation results.
- Added `AgentIntent.AddSessionNote` and `AgentIntent.AddStepNote` with `QueryParser` support for natural-language patterns such as `add note to session abc12345 ...` and `note for step FW-001 in session abc12345 ...`.
- `QueryParser` extracts session IDs for both note intents using the existing `SessionIdPattern` regex, avoiding unreliable hex-word heuristics that could steal CVE IDs or hashes from note text.
- `SecurityAgent.AskAsync` routes note intents through `GuidedRemediationService` and strips evidence syntax from note text via `ExtractEvidenceLinks`, which uses `Regex.Replace` callbacks to collect bracket (`[ref]`) and backtick (`` `ref` ``) references while removing the wrapper syntax from the stored text.
- `RemediationMarkdownFormatter` renders a `## Notes` section in exported session reports, grouping session notes under `### Session Notes` and step notes under `### Step Notes` (organized by rule ID), with timestamps, text, and bulleted evidence links.
- `AgentResultPresenter` renders a single-line confirmation message for `AddSessionNote`/`AddStepNote` results instead of falling through to the full remediation plan summary.
- 10+ new integration and edge-case tests covering full `AskAsync` routing, prefix stripping, empty note text, evidence syntax extraction, confidence/ambiguity scoring, and collision avoidance.
- Code: `VulcansTrace.Linux.Agent/Sessions/RemediationSession.cs`, `VulcansTrace.Linux.Agent/Reports/GuidedRemediationService.cs`, `VulcansTrace.Linux.Agent/SecurityAgent.cs`, `VulcansTrace.Linux.Agent/Query/QueryParser.cs`, `VulcansTrace.Linux.Agent/Query/AgentIntent.cs`, `VulcansTrace.Linux.Agent/Reports/RemediationMarkdownFormatter.cs`, `VulcansTrace.Linux.Avalonia/ViewModels/AgentResultPresenter.cs`, `VulcansTrace.Linux.Tests/Agent/SecurityAgentTests.cs`, `VulcansTrace.Linux.Tests/Agent/QueryParserTests.cs`

### Security Agent — Remediation Session Resume / History Browser
- Added `AgentIntent.ListRemediationSessions` and `AgentIntent.ResumeRemediation` with `QueryParser` support for `list my sessions`, `show sessions`, and `resume session <id>`.
- `GuidedRemediationService` now exposes `ListSessionsAsync`, `LoadSessionAsync`, and `DeleteSessionAsync` for full session store lifecycle management.
- `IAgent` interface extended with `ListRemediationSessionsAsync`, `LoadRemediationSessionAsync`, and `DeleteRemediationSessionAsync`.
- `RemediationSessionEventType` expanded with `SessionResumed` for audit traceability when sessions are reopened.
- Avalonia UI **Remediation Sessions** expander lists all persisted sessions with ID, status, rule ID, and creation time. Select a session and click **Resume** to reload it into chat, or **Delete** to remove it.
- CLI adds `session list`, `session show`, and `session delete` subcommands for headless session management.
- The session browser refreshes after session-producing operations so create, resume, verify, export, and delete actions stay visible without reopening the panel.
- `BuildSessionResult` accepts an optional `intent` parameter so resumed sessions report `ResumeRemediation` instead of hardcoding `StartRemediation`.
- Code: `VulcansTrace.Linux.Agent/Query/AgentIntent.cs`, `VulcansTrace.Linux.Agent/Query/QueryParser.cs`, `VulcansTrace.Linux.Agent/SecurityAgent.cs`, `VulcansTrace.Linux.Agent/IAgent.cs`, `VulcansTrace.Linux.Agent/Reports/GuidedRemediationService.cs`, `VulcansTrace.Linux.Agent/Sessions/RemediationSession.cs`, `VulcansTrace.Linux.Avalonia/ViewModels/AgentViewModel.cs`, `VulcansTrace.Linux.Avalonia/AgentView.axaml`, `VulcansTrace.Linux.Cli/Program.cs`, `VulcansTrace.Linux.Avalonia/ViewModels/AgentOperationRunner.cs`

### Notifications
- `NotifySendNotificationService` — Linux desktop notifications via `notify-send`.
  - Code: `VulcansTrace.Linux.Agent/Notifications/NotifySendNotificationService.cs`
- `EmailNotificationService` — SMTP email notifications with TLS support and configurable credentials via environment variables.
  - Code: `VulcansTrace.Linux.Agent/Notifications/EmailNotificationService.cs`
- `WebhookNotificationService` — HTTP POST JSON notifications with 3 retries and exponential backoff for transient failures (5xx, timeouts, connection errors). Implements `IDisposable`.
  - Code: `VulcansTrace.Linux.Agent/Notifications/WebhookNotificationService.cs`
- `INotificationService.NotifyAsync` marked `[Obsolete]` — unused, prefer `NotifyCriticalFindingsAsync`.
  - Code: `VulcansTrace.Linux.Agent/Notifications/INotificationService.cs`

### Packaging
- `scripts/publish-cli.sh` builds a self-contained `linux-x64` binary.
  - Script: `scripts/publish-cli.sh`

### Robustness and Security Hardening
- `AgentServices` implements `IDisposable` and properly disposes all store and notification service instances.
- `JsonFileScheduleStore` uses atomic file writes (temp file + move) to prevent JSON corruption on power loss.
- `InMemoryScheduleStore` is now thread-safe with `ReaderWriterLockSlim`.
- `CrontabManager.ReadCrontab` handles multiple cron implementations' empty-crontab messages.
- `CrontabManager.WriteCrontab` reads stderr asynchronously before `WaitForExit()` to prevent deadlocks on large stderr output.
- `CrontabManager.Install` rejects disabled schedules.
- CLI `ParseArg`/`TryParseArg` reject values starting with `--` to prevent flags from being consumed as values.
- Schedule name deduplication (case-insensitive) in CLI and GUI.
- `VT_EMAIL_NO_SSL` parsing supports `1`, `true`, and `yes` as disable-SSL values.
- `LastRunUtc` displayed with explicit `UTC` label in CLI list output.
- `ScheduleViewModel.Refresh` preserves DataGrid selection by ID across reloads.

### MITRE ATT&CK Navigator Layer Export
- Added `MitreTechnique` record to Core with `TechniqueId`, `TechniqueName`, `Tactic`, and `WhyItMatters` fields, with validation to prevent empty IDs.
- Added `MitreTechniques` to `Finding`, `IRule`, and `RuleResult` so every detection and rule can carry MITRE context.
- `MitreLayerBuilder` constructs Navigator-compatible layer JSON (format v4.5) with deterministic tactic-specific coverage aggregation, observed-finding scoring, and overridable version fields.
- All 13 engine detectors and all 12 security rule files now carry static `s_mitreTechniques` mappings.
- Evidence formatters (HTML, Markdown, CSV, STIX) include MITRE technique columns and fields.
- CLI `--output-mitre` flag exports a combined Navigator layer from configured detector/rule coverage plus any observed agent and engine findings.
- `EvidenceBuilder` automatically includes `mitre-navigator-layer.json` in every signed evidence ZIP.
- `RemediationSection` carries `MitreTechniques` for threat-contextualized remediation planning.
- Avalonia UI Findings and Rules DataGrids expose a **MITRE ATT&CK** column with searchable/displayable technique summaries.
- `RuleCatalogItem` and `RulesCatalog` flow MITRE techniques through the catalog and include them in search.
- 30+ new tests: `MitreTechniqueTests`, `MitreLayerBuilderTests` (empty, single, aggregate, dedup, gradient, custom name), `DetectorMitreMappingTests` (reflection-based static field verification), and formatter inclusion tests.
  - Code: `VulcansTrace.Linux.Core/MitreTechnique.cs`, `VulcansTrace.Linux.Evidence/MitreLayerBuilder.cs`, `VulcansTrace.Linux.Cli/Program.cs`, `VulcansTrace.Linux.Evidence/EvidenceBuilder.cs`, `VulcansTrace.Linux.Agent/Remediation/RemediationPlan.cs`, `VulcansTrace.Linux.Avalonia/MainWindow.axaml`, `VulcansTrace.Linux.Agent/Rules/RuleCatalogItem.cs`, `VulcansTrace.Linux.Agent/Rules/RulesCatalog.cs`, `VulcansTrace.Linux.Tests/Core/MitreTechniqueTests.cs`, `VulcansTrace.Linux.Tests/Evidence/MitreLayerBuilderTests.cs`, `VulcansTrace.Linux.Tests/Engine/DetectorMitreMappingTests.cs`

### Log Diff Mode
- Added `LogDiffAnalyzer` that compares two `AnalysisResult` instances to detect new, removed, and changed connection patterns and findings.
  - Events matched by a traffic pattern key (source IP, destination IP, destination port, protocol; source port wildcarded) with count deltas and dominant action shifts.
  - Findings matched by stable `Fingerprint` with `GroupBy` deduplication for duplicate fingerprints.
  - `LogDiffState` enum: `Unchanged`, `Added`, `Removed`, `Changed`. Count delta >20% or action shift marks `Changed`.
  - Code: `VulcansTrace.Linux.Engine/LogDiff/LogDiffAnalyzer.cs`, `LogDiffResult.cs`, `DiffEvent.cs`, `DiffFinding.cs`, `LogDiffState.cs`
- Added `LogDiffMarkdownFormatter` and `LogDiffHtmlFormatter` for standalone diff reports.
  - Code: `VulcansTrace.Linux.Evidence/Formatters/LogDiffMarkdownFormatter.cs`, `LogDiffHtmlFormatter.cs`
- Added CLI `diff` command with `--baseline`, `--incident`, `--intensity`, `--output-json`, `--output-html`, `--output-evidence`, and `--signing-key` flags. Exit code `2` when differences detected.
  - Code: `VulcansTrace.Linux.Cli/Program.cs`
- Added Avalonia `LogDiffWindow` with `LogDiffViewModel`, color-coded DataGrids, and `CompareLogsCommand` in `MainViewModel`.
  - Code: `VulcansTrace.Linux.Avalonia/Views/LogDiffWindow.axaml`, `ViewModels/LogDiffViewModel.cs`, `Converters/LogDiffStateToBrushConverter.cs`, `Converters/LogDiffStateToForegroundBrushConverter.cs`
- `EvidenceBuilder` includes `log-diff.md` and `log-diff.html` in signed ZIP when `LogDiffResult` provided.
  - Code: `VulcansTrace.Linux.Evidence/EvidenceBuilder.cs`
- Tests: `LogDiffAnalyzerTests` (added/removed/changed events and findings, source-port wildcard matching, action shift, count threshold), `DiffCommandTests` (CLI argument validation and evidence output), `LogDiffFormatterTests` (markdown and HTML coverage), `EvidenceBuilderTests` (bundle inclusion and omission).
  - Code: `VulcansTrace.Linux.Tests/Engine/LogDiffAnalyzerTests.cs`, `VulcansTrace.Linux.Tests/Cli/DiffCommandTests.cs`, `VulcansTrace.Linux.Tests/Evidence/LogDiffFormatterTests.cs`

### Documentation
- Portfolio and technical docs aligned to actual behavior and formats.
  - Docs: `README.md`, `docs/portfolio/` (17 implementation portfolios),
    `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, `docs/USAGE.md`,
    `docs/DEVELOPMENT.md`, `docs/HMAC_EVIDENCE.md`, `docs/SECURITY_AGENT.md`

### Security Agent — Adaptive Explanation Depth
- Added deterministic, history-aware depth tiers for single-rule explanations.
  - `ExplanationDepth` enum (`Standard`, `Familiar`, `Recurring`, `Escalating`) in `VulcansTrace.Linux.Agent/Explanations/ExplanationDepth.cs`.
  - `ExplanationDepthResolver` selects the tier from a `RuleMemoryEntry` using retained history length, closed remediation cycle count, and `RuleStatusTrend`. Worsening trend takes precedence over cycle count.
  - `AdaptiveExplanationBuilder` appends deterministic extra sections:
    - **Familiar**: brief history paragraph (retained snapshot count, first seen, trend).
    - **Recurring**: history plus category-specific **Root cause** guidance from `RuleCategoryResolver`.
    - **Escalating**: history plus **What changed** severity timeline; root cause is included when 2+ closed cycles also exist.
  - `LastVerifiedFixedUtc` is surfaced independently of closed-cycle count, so a verified-but-not-yet-returned rule still shows when it was last verified fixed without rendering a false "0 remediation cycle(s)" claim.
- `FindingExplanationService.ExplainFindingAsync` and `SingleRuleExplanationService.ExplainAsync` now accept the current rule-history dictionary and forward it to `AdaptiveExplanationBuilder`.
- `SecurityAgent.ExplainFindingAsync` passes `_auditState.Entities.RuleHistory` to the explanation service.
- Tests cover all four tiers, boundary conditions (zero cycles, mixed open/closed cycles, verified-fixed without cycles), stale-snapshot relative-time wording, and the verified-fixed refinement.
  - Code: `VulcansTrace.Linux.Agent/Explanations/ExplanationDepth.cs`, `ExplanationDepthResolver.cs`, `AdaptiveExplanationBuilder.cs`, `VulcansTrace.Linux.Agent/Reports/FindingExplanationService.cs`, `SingleRuleExplanationService.cs`, `VulcansTrace.Linux.Agent/SecurityAgent.cs`
  - Tests: `VulcansTrace.Linux.Tests/Agent/ExplanationDepthResolverTests.cs`, `FindingExplanationServiceTests.cs`, `SingleRuleExplanationServiceTests.cs`

### Live Stream / Real-Time Kernel Telemetry
- Added live stream pipeline that captures network events directly from the Linux kernel and runs the detector pipeline in real time.
- **Event sources:**
  - `SyntheticEventSource` — generates realistic traffic without privileges (port scans, beaconing, floods).
  - `PacketCaptureEventSource` — `AF_PACKET` raw socket with classic BPF filter (`SO_ATTACH_FILTER`), parses IP/TCP/UDP headers via P/Invoke to `libc`.
  - `NflogEventSource` — `AF_NETLINK` NFLOG group binding through `NFULNL_MSG_CONFIG`, parses structured netlink attributes including kernel timestamps.
- **Pipeline:** `LiveStreamWindow` with dual eviction (60 s / 10 000 events); dedicated `SentryAnalyzer` instance to avoid concurrency conflicts with batch analysis; `LiveStreamAnalyzer` deduplicates findings by fingerprint with 5-minute TTL; completed results flow through a bounded `DropOldest(64)` channel so stale UI updates do not stall analysis; live findings are capped at 1 000 (FIFO eviction).
- **UI:** Live Stream tab with source selection, privilege detection, live metrics, async stop (`StopAsync()` via `AsyncRelayCommand`), and `LiveResultReceived` wired into the main findings grid.
- **Structured event path:** Live events bypass `FormatAsIptablesLog` / `LogNormalizer` round-trip and feed directly into `SentryAnalyzer.Analyze(IReadOnlyList<UnifiedEvent>)`.
- **Action metadata:** Live events tagged `CAPTURED` (packet capture) or `LOGGED` (NFLOG) instead of `UNKNOWN`.
- **30 bug fixes** during code review: correct `AF_NETLINK` family, flat attribute flags, NFLOG payload/HWADDR/UID constants, `NFULNL_COPY_PACKET` mode request, double-close race, intensity threading, async stop, bounded findings, IDisposable caching, dedicated analyzer, result channel backpressure, realistic TTL, NFLOG timestamp parsing, kernel source fault surfacing, capability-aware source availability, retained parse-error samples, null guards, send errno handling, BPF length guards, delay clamping, structured overload, `LiveResultReceived` wiring, source name constants, and focused tests (VM, parser, config, formatter, stress).
- Code: `VulcansTrace.Linux.Engine/Live/*.cs`, `VulcansTrace.Linux.Avalonia/ViewModels/LiveStreamViewModel.cs`, `VulcansTrace.Linux.Avalonia/Views/LiveStreamView.axaml`, `VulcansTrace.Linux.Tests/Engine/Live/*`

### Safe Attack Replay / Demo Mode
- Added scenario-based safe attack replay on top of the live-stream pipeline. No privileges required; generates synthetic traffic that exercises real detectors.
- **Scenarios (`DemoScenario`):**
  - `RandomMix` — probabilistic blend of port scans, beaconing, and floods (legacy synthetic behavior).
  - `C2Beaconing` — zero-jitter periodic beaconing to an external destination; triggers `BeaconingDetector` and `C2ChannelDetector` and may emit an early low-severity `Novelty` signal before the repeated pattern matures. Recommended duration **150 s** at High intensity because `BeaconMinDurationSeconds = 120`.
  - `SshBruteforce` — high-volume SYN flood targeted at TCP/22; triggers `FloodDetector` plus admin-port spike evidence from `PrivilegeEscalationDetector`. Recommended duration **60 s** at High intensity.
  - `PrivilegeEscalation` — controlled sweep across admin ports (22, 3389, 5900, …); triggers `PrivilegeEscalationDetector` while staying below flood volume. Recommended duration **60 s** at High intensity.
- **Engine components:**
  - `DemoPatterns` — returns `SyntheticPatterns` per scenario (intervals, port targets, event volumes).
  - Named scenarios disable unrelated background traffic and use fixed sources/targets so exported demo evidence reflects the selected scenario. `RandomMix` keeps the older probabilistic stream.
  - `DemoRunner` — orchestrates a headless demo run via `LiveStreamAnalyzer`, collects findings, and returns `DemoResult` with `AnalysisResult`, `TraceMap`, actual elapsed `Duration`, and raw-log description for evidence export.
  - `DemoResult.Duration` stores **actual elapsed time** (`EndTime - StartTime`), not the configured parameter.
  - `DemoCompletedEventArgs` — surfaced by `LiveStreamViewModel` when a scenario finishes (auto-stop or manual stop).
- **CLI:** `vulcanstrace demo list` and `vulcanstrace demo run --scenario <keyword> [--duration <s>] [--intensity <level>] [--seed <int>] [--output-evidence <zip>] [--output-json <file>] [--output-html <file>] [--output-mitre <file>] [--signing-key <hex>]`.
  - Default duration is **150 s** so C2 beaconing works out of the box.
  - CLI demo evidence export now includes `risk-scorecard.html` and `risk-scorecard.md` because `RiskScorecardBuilder` is invoked after the run.
- **Avalonia UI:** Live Stream tab includes a scenario dropdown and a duration `NumericUpDown`. Selecting a scenario auto-sets the recommended duration (C2 Beaconing → 150 s; others → 60 s). Auto-stop timer fires after the configured duration and raises `DemoCompleted`, which `MainViewModel` handles to sync evidence, timeline, incident story, and risk scorecard.
- **Safety:** `LiveStreamViewModel.StopAsync()` uses `Interlocked.CompareExchange` reentrancy guard and marshals `DemoCompleted` to the UI thread via `Dispatcher.UIThread.Post` to prevent `ObservableCollection` modification from a background thread.
- `TraceMapCorrelator` is now wired into `AgentFactory.AgentServices` so demo evidence exports include correlated `trace-map.md`, `trace-map.json`, and `incident-story.md`.
- Code: `VulcansTrace.Linux.Engine/Live/DemoScenario.cs`, `DemoPatterns.cs`, `DemoRunner.cs`, `DemoResult.cs`, `DemoCompletedEventArgs.cs`
- Code: `VulcansTrace.Linux.Cli/Program.cs`
- Code: `VulcansTrace.Linux.Avalonia/ViewModels/LiveStreamViewModel.cs`, `MainViewModel.cs`, `MainWindow.axaml.cs`
- Tests: `DemoPatternsTests`, `DemoRunnerTests`, `LiveStreamViewModelTests`

### Tooling
- CLI test runner supports `--intensity`, `--all`, `--export`.
  - Tool: `tools/TestAnalysis/Program.cs`

### CIS Compliance Scorecard
- Added `ComplianceScorecardBuilder` implementing `IComplianceScorecardBuilder` for formal CIS compliance reporting.
- Computes per-control-family pass/fail/warn scores, overall rule-level percentage, and trend over time using `IAuditHistoryStore`.
- Thresholds: Pass ≥90%, Warn ≥80%, Fail <80%. Named constants (`PassThreshold`, `WarnThreshold`) on `ComplianceScorecard` prevent magic-number drift.
- `NotApplicable` rules are excluded from scoring; `Suppressed` rules are excluded from the applicable denominator.
- Multi-family rules count once per family for family scores, but overall score is computed at the rule level to avoid double-counting.
- Trend capped at the last 10 audit history entries to prevent unbounded growth.
- Evidence exports include `compliance-scorecard.html` and `compliance-scorecard.md` in the signed ZIP bundle.
- Avalonia UI has a new **Compliance** tab with overall score badge, family DataGrid, and mini bar-chart trend visualization.
- 42+ unit tests covering builder logic, `CisFamilyResolver`, formatters, ViewModel, and `ComplianceTrendAnalyzer`.
  - Code: `VulcansTrace.Linux.Core/Compliance/`, `VulcansTrace.Linux.Agent/Reports/ComplianceScorecardBuilder.cs`, `VulcansTrace.Linux.Evidence/Formatters/ComplianceScorecardHtmlFormatter.cs`, `VulcansTrace.Linux.Evidence/Formatters/ComplianceScorecardMarkdownFormatter.cs`, `VulcansTrace.Linux.Avalonia/Views/ComplianceScorecardView.axaml`, `VulcansTrace.Linux.Avalonia/ViewModels/ComplianceScorecardViewModel.cs`, `VulcansTrace.Linux.Tests/Agent/ComplianceScorecardBuilderTests.cs`, `VulcansTrace.Linux.Tests/Avalonia/ComplianceScorecardViewModelTests.cs`, `VulcansTrace.Linux.Tests/Evidence/ComplianceScorecardFormatterTests.cs`

### Risk Scorecard
- Added `RiskScorecardBuilder` implementing `IRiskScorecardBuilder` for aggregate risk scoring.
- Computes numeric score (0–100), letter grade (A–F), summary status, and per-category breakdown from agent findings.
- Scoring formula: deduction per finding = `SeverityValue × 5 × AverageControlWeight`. Control weight is the average of `CisBenchmarkMapping.ControlWeight` values for the finding's CIS mappings (default 1.0).
- Defense-in-depth guards: `ControlWeight` values that are ≤0, NaN, Infinity, or >1000.0 fall back to 1.0 to prevent silent scoring bypasses and numeric overflow.
- Grade is computed from the raw score before rounding; display uses `Math.Round(..., 1, MidpointRounding.AwayFromZero)`.
- Summary status mapping: A→Low, B→Moderate, C→Elevated, D→High, F→Severe (monotonic severity progression).
- Only risk-relevant findings contribute; Info findings (severity = 0) are excluded from both the score and `TotalFindings`.
- `AgentIntent.RiskScore` and `QueryParser` keywords (`risk score`, `risk grade`, `what's my risk`, `how risky`, `risk assessment`, `overall risk`) let users ask for their risk grade in chat.
- `SecurityAgent` computes the scorecard automatically during audits via injected `IRiskScorecardBuilder` (defaults to `new RiskScorecardBuilder()` when not supplied).
- `AgentReportGenerator` forwards `RiskScorecard` from `AgentResult` to `AnalysisResult`.
- Evidence exports include `risk-scorecard.html` and `risk-scorecard.md` in the signed ZIP bundle.
- Avalonia UI has a new **Risk Score** tab with color-coded grade badge, numeric score, summary status, and per-category DataGrid.
- 25+ unit tests covering builder logic, grade boundaries, control-weight guards (zero, negative, max value), raw-score grading, category ordering, and ViewModel behavior.
  - Code: `VulcansTrace.Linux.Core/RiskScorecard.cs`, `VulcansTrace.Linux.Core/CategoryRisk.cs`, `VulcansTrace.Linux.Agent/Reports/RiskScorecardBuilder.cs`, `VulcansTrace.Linux.Agent/Reports/IRiskScorecardBuilder.cs`, `VulcansTrace.Linux.Evidence/Formatters/RiskScorecardHtmlFormatter.cs`, `VulcansTrace.Linux.Evidence/Formatters/RiskScorecardMarkdownFormatter.cs`, `VulcansTrace.Linux.Avalonia/ViewModels/RiskScorecardViewModel.cs`, `VulcansTrace.Linux.Tests/Agent/RiskScorecardBuilderTests.cs`, `VulcansTrace.Linux.Tests/Avalonia/RiskScorecardViewModelTests.cs`

### Security Agent — "Alive Without Being Alive" Enhancements
Implemented six incremental build phases to make the deterministic, local agent feel context-aware and proactive without introducing an external LLM or sending system data anywhere.

- **Phase 1 — Per-rule memory**
  - Added `RuleMemoryEntry`, `RuleSeveritySnapshot`, and `RuleStatusTrend` in `VulcansTrace.Linux.Agent/Memory/`.
  - Added `IRuleMemoryRecorder` / `RuleMemoryRecorder`; records one snapshot per rule per audit using the worst severity among all findings for that rule.
  - Tracks `FirstSeenUtc`, `LastSeenUtc`, `LastVerifiedFixedUtc`, a rolling severity history, and a deterministic status trend (`New`, `Stable`, `Improving`, `Worsening`).
  - Memory is grouped by `RuleId` so repeated targets do not create duplicate history entries.
  - Code: `VulcansTrace.Linux.Agent/Memory/RuleMemoryEntry.cs`, `RuleSeveritySnapshot.cs`, `RuleStatusTrend.cs`, `IRuleMemoryRecorder.cs`, `RuleMemoryRecorder.cs`
  - Tests: `VulcansTrace.Linux.Tests/Agent/Memory/RuleMemoryRecorderTests.cs`

- **Phase 2 — Frame-based NLU**
  - Added `QueryEntityFrame` and `IEntityExtractor` / `EntityExtractor`.
  - Extracts rule IDs, categories, session IDs, severity filters, time windows, remediation verbs, and ordinals from free-text queries using deterministic regex and word-boundary matching.
  - `DialogueManager` enriches the parsed query with the entity frame before inference, and `SecurityAgent` uses extracted entities for follow-up resolution. Low-score queries still keep their entity frame so inputs such as `verify finding FW-001` can be routed correctly.
  - Code: `VulcansTrace.Linux.Agent/Query/QueryEntityFrame.cs`, `VulcansTrace.Linux.Agent/Query/IEntityExtractor.cs`, `VulcansTrace.Linux.Agent/Query/EntityExtractor.cs`, `VulcansTrace.Linux.Agent/Dialogue/DialogueManager.cs`
  - Tests: `VulcansTrace.Linux.Tests/Agent/EntityExtractorTests.cs`, `VulcansTrace.Linux.Tests/Agent/QueryParserTests.cs`

- **Phase 3 — Posture correlation**
  - Added `PostureCorrelation`, `PostureCorrelationPattern`, `IPostureCorrelator`, and `PostureCorrelator` in `VulcansTrace.Linux.Engine`.
  - Built-in correlation patterns include `FW-002+SSH-002`, `FW-004+PORT-*`, and `USER-001+SSH-002`.
  - Correlations are deduplicated by `(PatternId, RuleIdA, RuleIdB)` and rendered in the narrative with both rule IDs so every correlation claim is traceable.
  - Code: `VulcansTrace.Linux.Engine/PostureCorrelator.cs`, `VulcansTrace.Linux.Engine/PostureCorrelation.cs`, `VulcansTrace.Linux.Engine/PostureCorrelationPattern.cs`, `VulcansTrace.Linux.Engine/IPostureCorrelator.cs`
  - Tests: `VulcansTrace.Linux.Tests/Engine/PostureCorrelatorTests.cs`

- **Phase 3.5 — Cross-scanner confidence validation**
  - Added `CrossScannerValidator` and `CrossScannerValidationSignal` in `VulcansTrace.Linux.Agent.Analysis`.
  - After rule findings are assembled and noise-budgeted, the validator checks each Critical/High/Medium finding against independent `ScanData` sources. Support adds a `CrossScannerValidation` evidence signal and raises `DetectionConfidence` one level, capped at `High`; contradiction adds a `CrossScannerValidation` evidence signal and lowers confidence one level, down to `Unknown`; neutral data leaves confidence unchanged.
  - Only data sources with `CapabilityStatus.Available` are trusted; `PermissionLimited` or `Unavailable` sources are skipped rather than interpreted as support or contradiction.
  - Initial validation registry: `FW-002` (High branch only) with port/network interfaces, `PORT-002` and `PORT-003` against firewall ACCEPT/no-firewall or DROP/REJECT, `SSH-002` against running SSH service plus listener, `SRV-001` against telnet listener, and `USER-001` against reachable SSH path.
  - `AuditDiffCalculator` suppresses support-only `Low` ↔ `Medium` confidence transitions as scanner-availability noise; contradiction-driven confidence changes still surface.
  - Code: `VulcansTrace.Linux.Agent/Analysis/CrossScannerValidator.cs`, `VulcansTrace.Linux.Agent/Analysis/CrossScannerValidationSignal.cs`, `VulcansTrace.Linux.Agent/Reports/AuditDiffCalculator.cs`
  - Tests: `VulcansTrace.Linux.Tests/Agent/Analysis/CrossScannerValidatorTests.cs`, `VulcansTrace.Linux.Tests/Agent/AuditDiffCalculatorTests.cs`

- **Phase 4 — NLG composition**
  - Added `Narrative`, `INarrativeComposer`, and `NarrativeComposer`.
  - Composes multi-paragraph prose from findings, rule-memory history, and posture correlations.
  - Every non-generic paragraph cites source IDs in its rendered text; `Narrative.SourceIds` collects the IDs for automated traceability checks.
  - `AgentResult.Narrative` carries the composed text and source list through the UI, CLI, and evidence pipeline; evidence bundles write it as `agent-narrative.md`.
  - Code: `VulcansTrace.Linux.Agent/Dialogue/Narrative.cs`, `INarrativeComposer.cs`, `NarrativeComposer.cs`, `VulcansTrace.Linux.Agent/SecurityAgent.cs`
  - Tests: `VulcansTrace.Linux.Tests/Agent/NarrativeComposerTests.cs`

- **Phase 5 — Proactive suggestions**
  - Extended `AgentSuggestionProvider` to suggest correlated-pair fixes, current stale/worsening prioritization, and related fixes after verification.
  - Suggestions remain deterministic and grounded in `AgentResult` and `EntityFrame`; no external model is used.
  - Code: `VulcansTrace.Linux.Agent/Suggestions/AgentSuggestionProvider.cs`, `VulcansTrace.Linux.Agent/Suggestions/SuggestedFollowUp.cs`
  - Tests: `VulcansTrace.Linux.Tests/Agent/Suggestions/AgentSuggestionProviderTests.cs`

- **Phase 6 — Verify loop**
  - Added `SecurityAgent.VerifyFindingAsync(ruleId)` and the CLI command `vulcanstrace verify-finding <rule-id>`.
  - Re-runs the last audit intent, reports whether the requested finding is still present, and stamps `LastVerifiedFixedUtc` in rule memory when the finding is resolved.
  - Natural-language inputs such as `verify finding FW-001` route to targeted verification, while 8-character session IDs still route to session verification.
  - Updates the narrative and follow-up suggestions after verification.
  - Code: `VulcansTrace.Linux.Agent/SecurityAgent.cs`, `VulcansTrace.Linux.Agent/IAgent.cs`, `VulcansTrace.Linux.Cli/Program.cs`, `VulcansTrace.Linux.Agent/Memory/RuleMemoryRecorder.cs`
  - Tests: `VulcansTrace.Linux.Tests/Agent/Memory/SecurityAgentMemoryIntegrationTests.cs`

- **Display polish**
  - Avalonia `MarkdownInlinesConverter` renders `**bold**` and `*italic*` as styled Inlines while ignoring intraword `_` so snake_case identifiers remain intact.
  - CLI strips markdown markers from agent narrative text for clean terminal output.
  - Evidence exports include `agent-narrative.md` and `posture-correlations.md` when those agent fields are present.
  - Code: `VulcansTrace.Linux.Avalonia/Converters/MarkdownInlinesConverter.cs`, `VulcansTrace.Linux.Cli/Program.cs`, `VulcansTrace.Linux.Agent/Reports/AgentReportGenerator.cs`, `VulcansTrace.Linux.Evidence/EvidenceBuilder.cs`

- **Bug-fix pass**
  - Fixed `VerifyFindingAsync` memory persistence by writing updated rule history back to the entity frame and saving the cross-session memory snapshot.
  - Fixed user-facing targeted verification routing from chat and CLI.
  - Fixed stale rule-memory suggestions so they only reference findings present in the current result.
  - Fixed evidence export propagation for agent narratives and posture correlations.
  - Grouped `RuleMemoryRecorder` snapshots by `RuleId` to prevent duplicate history entries across multiple targets for the same rule.
  - Deduplicated `PostureCorrelator` output with a per-result key set.
  - Hardened `EntityExtractor` verb/category matching with word boundaries and substring category detection.
  - Strengthened narrative traceability so the posture-correlation paragraph always cites both rule IDs.
  - Fixed intraword `_` italic mangling in Avalonia markdown rendering.
  - Hardened `ParseStepNoteQuery` against session-ID misidentification by using a dedicated regex that does not steal CVE IDs or hashes from note text.
  - Cross-session memory snapshot retention increased from 30 to **90 days**.

### Agent Dialogue and Memory Hardening

- **Intent disambiguation**
  - Removed the ambiguous bare `"check"` mapping from `EntityExtractor.RemediationVerbKeywords` so generic audit queries such as `"check my firewall"` and `"check FW-001"` no longer get pulled into `VerifyRemediation`.
  - Hardened all `IntentInferenceEngine.LooksLike*` probes to use whole-word/phrase-boundary matching, eliminating substring false positives such as `notebook` → `NoteRequest` or `prefix` → `FixRequest`.
  - Code: `VulcansTrace.Linux.Agent/Query/EntityExtractor.cs`, `VulcansTrace.Linux.Agent/Dialogue/IntentInferenceEngine.cs`, `VulcansTrace.Linux.Agent/Dialogue/DialogueManager.cs`
  - Tests: `VulcansTrace.Linux.Tests/Agent/Dialogue/IntentInferenceEngineTests.cs`, `VulcansTrace.Linux.Tests/Agent/Dialogue/DialogueManagerTests.cs`

- **Remediation history in continuity narrative**
  - Added `IRuleMemoryRecorder.MarkRemediationAttempt()` and implemented it in `RuleMemoryRecorder`.
  - `SecurityAgent` now stamps `LastRemediationAttemptUtc` only after observable remediation progress: guided session steps marked in-progress/completed/failed or live CLI auto-fix apply commands.
  - `NarrativeComposer.ComposeMemory()` surfaces both `LastRemediationAttemptUtc` and `LastVerifiedFixedUtc` in the continuity paragraph, e.g.:
    - "A remediation was attempted 3 days ago."
    - "It was verified fixed 1 week ago but has returned."
  - Fixed singular/plural relative-time formatting ("1 week ago" instead of "1 weeks ago").
  - Code: `VulcansTrace.Linux.Agent/Memory/IRuleMemoryRecorder.cs`, `VulcansTrace.Linux.Agent/Memory/RuleMemoryRecorder.cs`, `VulcansTrace.Linux.Agent/SecurityAgent.cs`, `VulcansTrace.Linux.Agent/Dialogue/NarrativeComposer.cs`
  - Tests: `VulcansTrace.Linux.Tests/Agent/Memory/RuleMemoryRecorderTests.cs`, `VulcansTrace.Linux.Tests/Agent/NarrativeComposerTests.cs`

### Security Agent — Deepening the Instincts (Attack Chains, Trajectory, Proactivity, Remediation Wisdom)

Extended the deterministic, local agent with four narrative capabilities that build on existing machinery (findings, MITRE mappings, per-rule memory, posture correlations) without adding an external LLM or sending data anywhere.

- **Attack Chain Narratives**
  - Added deterministic kill-chain stage mapping (`AttackChainStageMapping`) for relevant rule IDs (e.g., `FW-002` → Reconnaissance, `SSH-002` → Credential Access, `SSH-001` → Execution).
  - Added `AttackChainNarrator` that builds ordered attack chains from posture correlations and deterministic continuation-graph traversal, cites rule IDs and MITRE technique IDs, and renders paths such as "FW-002 (T1562.004) → SSH-002 (T1021.004, T1110) → SSH-001 (T1021.004, T1110)".
  - Added `AttackChain` / `AttackChainLink` records to Core and surfaced them in `AgentResult.AttackChains`.
  - Code: `VulcansTrace.Linux.Agent/Analysis/AttackChainStageMapping.cs`, `AttackChainNarrator.cs`, `VulcansTrace.Linux.Core/AttackChain.cs`, `AttackChainStage.cs`
  - Tests: `VulcansTrace.Linux.Tests/Agent/AttackChainNarratorTests.cs`

- **System Trajectory Intelligence**
  - Added `SystemTrajectoryAnalyzer` that aggregates per-rule `RuleStatusTrend` values and verified-fixed absent rules into a system-level direction (`Improving`, `Worsening`, `Stable`), weighted by severity.
  - Added `SystemTrajectory` record to Core and surfaced it in `AgentResult.SystemTrajectory`.
  - Narrative renders the net direction and cites example rule IDs; ellipsis is shown when more than three example rules exist.
  - Code: `VulcansTrace.Linux.Agent/Analysis/SystemTrajectoryAnalyzer.cs`, `VulcansTrace.Linux.Core/SystemTrajectory.cs`
  - Tests: `VulcansTrace.Linux.Tests/Agent/SystemTrajectoryAnalyzerTests.cs`

- **Proactive Volunteering**
  - Added `ProactiveAlertDetector` that flags current findings whose rule was previously verified fixed, surfacing them in `AgentResult.ProactiveAlerts` before `LastVerifiedFixedUtc` is consumed and attaching category-specific regression guidance.
  - Narrative renders an alert such as "[SSH-002] returned after being verified fixed 3 days ago. Something re-applied the insecure configuration..."
  - Alerts are deduplicated by rule ID and guarded against same-audit false positives.
  - Code: `VulcansTrace.Linux.Agent/Analysis/ProactiveAlertDetector.cs`, `VulcansTrace.Linux.Core/ProactiveAlert.cs`
  - Tests: `VulcansTrace.Linux.Tests/Agent/ProactiveAlertDetectorTests.cs`

- **Remediation Wisdom**
  - Added `RemediationCycle` to `RuleMemoryEntry`; `RuleMemoryRecorder` opens a pending cycle on real remediation attempts, completes the verified-fixed phase on `MarkVerifiedFixed`, and closes it when the rule is seen failing again.
  - Added `RemediationWisdomAnalyzer` that counts closed cycles and emits category-specific guidance for rules with two or more fix-and-return cycles.
  - Added `RuleCategoryResolver` to centralize rule-prefix parsing and guidance text.
  - Narrative renders "[SSH-002] has been fixed and returned 3 times... check your playbooks."
  - Code: `VulcansTrace.Linux.Agent/Memory/RemediationCycle.cs`, `VulcansTrace.Linux.Agent/Analysis/RemediationWisdomAnalyzer.cs`, `RuleCategoryResolver.cs`, `VulcansTrace.Linux.Core/RemediationWisdom.cs`
  - Tests: `VulcansTrace.Linux.Tests/Agent/RemediationWisdomAnalyzerTests.cs`, `VulcansTrace.Linux.Tests/Agent/Rules/RuleCategoryResolverTests.cs`

- **Bug-fix pass**
  - Added duplicate-cycle guard so a single verified-fix timestamp cannot create multiple remediation cycles.
  - `RuleMemoryRecorder.Record` now consumes `LastVerifiedFixedUtc` when a failing rule has a pending verified-fix timestamp, preventing chronic proactive alerts and duplicate cycle creation.
  - Reordered `SecurityAgent.RunAuditCoreAsync` so `ProactiveAlertDetector` runs before `Record`.
  - Deduped `ProactiveAlertDetector` and `RemediationWisdomAnalyzer` inputs by rule ID to avoid duplicate entries for multi-finding rules.
  - Deduped `AttackChainNarrator` links by rule ID, keeping the highest-severity link.
  - Prevented attack-chain narratives from being created by stage order alone; chains now require a posture-backed seed and extend through deterministic continuation-graph traversal.
  - Added deterministic attack-chain opening variation so multiple rendered chains do not all begin with the same sentence.
  - Added category-specific proactive-alert regression guidance via `RuleCategoryResolver`.
  - Corrected the `USER-001` chain rationale to describe additional UID-0 accounts instead of weak password policy.
  - Counted verified-fixed rules that are absent from current findings as improving trajectory signals.
  - Remediation attempts now open pending `RemediationCycle` records instead of only updating `LastRemediationAttemptUtc`.
  - Added ellipsis in trajectory examples when more than three rules are cited.
  - Added attack-chain source pattern IDs to `Narrative.SourceIds`.
  - Preserved original attempt timestamps when `MarkVerifiedFixed` is called multiple times for the same open cycle.
  - Tests: updated `RuleMemoryRecorderTests.cs`, `NarrativeComposerTests.cs`, `JsonFileAgentMemoryStoreTests.cs`

## 2) Profiles and Their Capabilities

Profiles are defined in:
`VulcansTrace.Linux.Engine/Configuration/AnalysisProfileProvider.cs`

Profiles do not use the same detector set. The differences are:
- Which detectors are enabled.
- How aggressive the thresholds are.
- The minimum severity displayed in results.

### Detectors (What They Find)
- PortScan: many distinct destination ports from a single source in a window.
- Flood (DoS): very high event rates from a single source.
- LateralMovement: same source touching multiple internal hosts.
- Beaconing: periodic, low-variance intervals between communications.
- PolicyViolation: disallowed outbound ports or policy rule hits.
- Novelty: rare host/port combinations within the analyzed log.
- FlagAnomaly: suspicious TCP flag patterns (only when flags are present).
- MacSpoofing: same IP associated with multiple MAC addresses within a window.
- KernelModule: posture assessment via firewall module signature scanning (conntrack, rate limiting, Layer 7, quota/hashlimit, IPv6).
- InterfaceHopping: rapid interface changes tied to traffic patterns.
- UnusualPacketSize: anomalous packet size distributions.
- C2Detection: repeatable timing patterns suggestive of C2 channels.
- PrivilegeEscalationDetection: spikes/sweeps against admin ports.

### Severity visibility (filtering)
- Low: only shows Severity.High and above.
- Medium: shows Severity.Medium and above.
- High: shows all severities (Severity.Info and above).

### Profile characteristics and thresholds

LOW (Conservative)
- Enabled detectors:
  - PortScan, Flood, LateralMovement, Beaconing, PolicyViolation
  - FlagAnomaly, MacSpoofing
- Disabled detectors:
  - Novelty, KernelModule, InterfaceHopping, UnusualPacketSize, C2Detection,
    PrivilegeEscalationDetection
- Thresholds:
  - PortScanMinPorts = 30 (5 min window)
  - FloodMinEvents = 400 (60 sec window)
  - LateralMinHosts = 6 (10 min window)
  - BeaconMinEvents = 8, BeaconStdDevThreshold = 3.0,
    BeaconMinIntervalSeconds = 60, BeaconMaxIntervalSeconds = 900
- C2 thresholds are defined but C2 detection is disabled in Low.
  - C2ToleranceSeconds = 10.0, C2MinIntervalSeconds = 120,
    C2MaxIntervalSeconds = 3600, C2MinOccurrences = 5,
    C2MinPatternEvents = 10, C2MinGroupSize = 4
- Privilege escalation: spike window = 10 minutes, min attempts = 8, sweep min distinct = 4 (detector disabled).
  - InterfaceHoppingWindowMinutes = 10
  - MacSpoofingWindowMinutes = 10
  - PacketSizeLargeThreshold = 4000, PacketSizeSmallThreshold = 20,
    PacketSizeMinForAnalysis = 15, PacketSizeConsistencyPercent = 80,
    PacketSizeMinConsistentCount = 15, PacketSizeVarianceRatio = 0.6,
    PacketSizeMinAvgForVariance = 150
- AdminPorts = [445, 3389, 22]
- DisallowedOutboundPorts = [21, 23, 445]
- MaxFindingsPerDetector = 100 (group cap — similar findings are grouped before the budget is applied)
- MinSeverityToShow = High

MEDIUM (Balanced)
- Enabled detectors:
  - PortScan, Flood, LateralMovement, Beaconing, PolicyViolation, Novelty
  - FlagAnomaly, MacSpoofing, KernelModule, InterfaceHopping,
    UnusualPacketSize, C2Detection, PrivilegeEscalationDetection
- Thresholds:
  - PortScanMinPorts = 15 (5 min window)
  - FloodMinEvents = 200 (60 sec window)
  - LateralMinHosts = 4 (10 min window)
  - BeaconMinEvents = 6, BeaconStdDevThreshold = 5.0,
    BeaconMinIntervalSeconds = 30, BeaconMaxIntervalSeconds = 900
  - C2ToleranceSeconds = 5.0, C2MinIntervalSeconds = 60,
    C2MaxIntervalSeconds = 1800, C2MinOccurrences = 3,
    C2MinPatternEvents = 6, C2MinGroupSize = 3
  - PrivilegeSpikeWindowMinutes = 5, PrivilegeSpikeMinAttempts = 5,
    PrivilegeSweepMinDistinctPorts = 3
  - InterfaceHoppingWindowMinutes = 5
  - MacSpoofingWindowMinutes = 5
  - PacketSizeLargeThreshold = 3000, PacketSizeSmallThreshold = 40,
    PacketSizeMinForAnalysis = 10, PacketSizeConsistencyPercent = 70,
    PacketSizeMinConsistentCount = 10, PacketSizeVarianceRatio = 0.5,
    PacketSizeMinAvgForVariance = 100
- AdminPorts = [445, 3389, 22]
- DisallowedOutboundPorts = [21, 23, 445]
- MaxFindingsPerDetector = 100 (group cap — similar findings are grouped before the budget is applied)
- MinSeverityToShow = Medium

HIGH (Aggressive)
- Enabled detectors:
  - All detectors enabled (same set as Medium, with more aggressive thresholds)
- Thresholds:
  - PortScanMinPorts = 8 (5 min window)
  - FloodMinEvents = 100 (60 sec window)
  - LateralMinHosts = 3 (10 min window)
  - BeaconMinEvents = 4, BeaconStdDevThreshold = 8.0,
    BeaconMinIntervalSeconds = 10, BeaconMaxIntervalSeconds = 900
  - C2ToleranceSeconds = 8.0, C2MinIntervalSeconds = 30,
    C2MaxIntervalSeconds = 1800, C2MinOccurrences = 2,
    C2MinPatternEvents = 4, C2MinGroupSize = 3
  - PrivilegeSpikeWindowMinutes = 10, PrivilegeSpikeMinAttempts = 4,
    PrivilegeSweepMinDistinctPorts = 2
  - InterfaceHoppingWindowMinutes = 10
  - MacSpoofingWindowMinutes = 10
  - PacketSizeLargeThreshold = 2000, PacketSizeSmallThreshold = 60,
    PacketSizeMinForAnalysis = 5, PacketSizeConsistencyPercent = 60,
    PacketSizeMinConsistentCount = 5, PacketSizeVarianceRatio = 0.4,
    PacketSizeMinAvgForVariance = 80
- AdminPorts = [445, 3389, 22]
- DisallowedOutboundPorts = [21, 23, 445]
- MaxFindingsPerDetector = 100 (group cap — similar findings are grouped before the budget is applied)
- MinSeverityToShow = Info

## 3) Notes on Findings Behavior

- Low is intentionally quiet: the detector thresholds are high, and findings
  below Severity.High are filtered out. This is by design for conservative triage.
- Medium is the general-purpose setting for daily analysis.
- High is best for threat-hunting and forensic review where false positives are
  acceptable in exchange for coverage.
- FlagAnomaly ignores missing flags to avoid false positives from incomplete
  log lines.
- The per-category noise budget groups semantically similar findings before capping.
  A detector or Agent rule that produces 500 repeated findings for different
  targets can emit one representative group with `GroupedCount = 500`, not 500
  separate rows. The budget only trims when there are more than 100 distinct
  semantic groups in the same category.

## 4) Quick Capability Mapping (Logs in the Chatbox)

For iptables/nftables logs pasted into the app, the profiles can find:

LOW
- Correlated port scans that are escalated to Critical; standalone PortScan
  findings are Medium severity and hidden by Low's visibility filter
- Extreme floods (very high event bursts)
- Broad lateral movement (many internal hosts)
- High-confidence beaconing
- Policy violations on disallowed outbound ports
- Flag anomalies (only when flags are present)
- MAC spoofing

MEDIUM
- All Low findings, plus:
- Moderate port scans, floods, and lateral movement
- Novelty detection for new hosts/ports
- Kernel module and interface hopping anomalies (when present in logs)
- Unusual packet sizes
- C2 channels with moderate regularity
- Privilege escalation spikes/sweeps on admin ports

HIGH
- All Medium findings, plus:
- Lower-threshold port scans, floods, lateral movement, and beaconing
- More sensitive C2 detection
- Lower-threshold privilege escalation detection (same 10-minute window as Low, but fewer attempts required)
- Visibility for all severities (Info and above)
