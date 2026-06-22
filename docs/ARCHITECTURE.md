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

## Doctor Components

- `DoctorService` — read-only probe that runs `ScannerCoordinator` against all configured scanners and returns `DoctorResult` with capability records and warnings, reusing the same `IScanner` instances and `AgentResultComposer` formatting used during full audits.
- `DoctorResult` — immutable diagnostic result containing normalized `Capabilities` (`DataSourceCapability` records), `Warnings` (scanner failure or permission messages), and computed aggregate availability counts for available, unavailable, permission-limited, and not-checked sources.
- `DoctorCommand` (CLI) — `vulcanstrace doctor [--output-json <file>]`, prints a color-coded summary and exits `0` (all normalized sources available), `1` (at least one unavailable source or runtime error), `2` (permission-limited or not-checked sources only), or `130` (cancelled).
- `DoctorViewModel` / `DoctorCapabilityViewModel` — Avalonia bindings for the Doctor tab: busy state, summary color/background, warnings banner, and capability grid.
- `DoctorView` — Avalonia tab UI with **Run Diagnostic**, summary banner, warnings banner, and normalized capability list; empty-state prompt shown before the first probe.

## Demo Mode Components

- `DemoScenario` — enum identifying pre-defined safe attack-replay scenarios (`RandomMix`, `C2Beaconing`, `SshBruteforce`, `PrivilegeEscalation`).
- `DemoScenarioNames` — display-name, CLI keyword, and description mappings with round-trip parsing.
- `DemoPatterns` — returns `SyntheticPatterns` per scenario (beacon intervals, port targets, event volumes, admin port sweeps).
- `DemoRunner` — orchestrates headless demo runs through `LiveStreamAnalyzer`, aggregates findings, builds `TraceMap` via `TraceMapCorrelator`, and returns `DemoResult` with actual elapsed duration.
- `DemoResult` — completed artifacts: `AnalysisResult`, `TraceMap`, `RawLogDescription`, `Duration` (actual, not configured), and timing metadata.
- `DemoCompletedEventArgs` — event args raised by `LiveStreamViewModel` when a scenario finishes, including the findings from that demo run only. `MainViewModel` consumes it to sync evidence, timeline, incident story, and risk scorecard without mixing in stale audit findings.
- `TraceMapCorrelator` — wired into `AgentFactory.AgentServices` so demo evidence exports include correlated attack chains (`trace-map.md`, `trace-map.json`, `incident-story.md`).

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
7. Findings are filtered by the profile's minimum severity (`MinSeverityToShow`), then grouped by a semantic noise key and passed through a per-category noise budget (`MaxFindingsPerDetector`). Rule-backed findings group by rule ID, category, source host, and short description; detector findings without a rule ID also include details so distinct C2 intervals stay separate. Each group produces one representative finding with merged time ranges, a `GroupedCount`, `RepresentativeTargets`, and `RiskDrivers`. The budget caps group count, not raw findings, and emits a warning when the budget is exceeded.
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

1. A natural-language query is parsed into an `AgentIntent` by `QueryParser`, then resolved through `DialogueManager` which applies anaphora resolution and topic-aware deterministic inference before `SecurityAgent` routes the final `AgentQuery`.
2. `ScannerCoordinator` runs agent scanners and builds a `ScanData` snapshot containing firewall, port, service, SSH daemon configuration, file permissions, filesystem audit findings, kernel and system hardening parameters, user accounts, shadow entries, password aging, PAM configuration, logging and audit configuration, cron job entries and script permissions, installed package inventory and pending security updates, unattended-upgrades configuration, interface, route, connection state, container runtime state, Kubernetes pod security posture, live process runtime state, YARA rule matches, and data-source capability status for local Linux commands.
3. `RuleEvaluationService` filters rules by intent, resolves role-aware policy from built-in defaults and local JSON overrides, invokes contextual rules when supported, converts rule crashes into explicit results, and applies auto-pass or severity override policy.
4. `FindingAssemblyService` converts failed rule results into `Finding` records with stable fingerprints, markdown-backed explanations, suppression status, and dual-layer CIS Benchmark mappings.
5. `CrossScannerValidator` checks Critical and High findings against independent `ScanData` sources. Support adds a `CrossScannerValidation` evidence signal and raises confidence one level, capped at `High`; contradiction adds the same source signal and lowers confidence one level, down to `Unknown`. It never removes the original finding and only trusts data sources whose capability status is `Available`. Medium findings are intentionally deferred from this phase. Rules that draw from only one scanner (for example, `FW-001`, `FW-004`, `NET-003`, and all container/Kubernetes rules) are intentionally excluded because validation would be tautological.
6. `FindingExplanationService` and `SingleRuleExplanationService` apply **adaptive explanation depth** when explaining a finding: `ExplanationDepthResolver` selects a tier from the rule's `RuleMemoryEntry` (history length, closed remediation cycles, trend), and `AdaptiveExplanationBuilder` appends deterministic history, root-cause, or escalation paragraphs without LLM reasoning.
7. `AgentLogAnalysisService` optionally analyzes pasted firewall logs through `SentryAnalyzer`.
8. `AgentResultComposer` builds user-facing summaries and deterministic data-source capability reports.
9. `AgentResultFinalizer` attaches scorecard output and builds the final `AgentResult`, including posture correlations and attack chains so they are persisted with the audit history entry.
10. `RuleMemoryRecorder` records per-rule severity snapshots, trends, and remediation cycles.
11. `CategoryCoverageRecorder` records which audit category was just checked. A targeted audit intent records one category; `FullAudit` records all 17 categories. The timestamped list is stored in the entity frame and persisted in the cross-session memory snapshot.
12. `SystemTrajectoryAnalyzer` aggregates per-rule trends and verified-fixed absent rules into a system-level trajectory.
13. `RemediationWisdomAnalyzer` detects rules with repeated fix-and-return cycles.
14. `NarrativeComposer` builds the multi-paragraph narrative from findings, correlations, attack chains, proactive alerts, trajectory, remediation wisdom, memory, and category coverage.
15. `AgentSuggestionProvider` generates deterministic follow-up suggestions, including blind-spot chips after partial audits.
16. `DialogueContext`/`AgentAuditState` remembers the fully enriched result so every follow-up intent sees the same attack chains, correlations, and metadata that were displayed to the user.

The `ShowEvidence` follow-up path is handled by `EvidenceProvenanceService`:

- It looks up the referenced finding in the remembered audit result or runs the single rule fresh if only a rule ID is known.
- It builds a deterministic evidence-chain markdown response from scanner source/commands, raw evidence signals, rule rationale, CIS/MITRE mappings, attack-chain membership, and per-rule history.
- `ReferenceResolver` (shared with `FindingExplanationService`) handles bare category words: if the focused finding's category matches the query word, that finding is used instead of an arbitrary category match.

The audit history store (`JsonFileAuditHistoryStore` / `InMemoryAuditHistoryStore`) keeps the newest entries fully detailed and replaces older retained entries with slim summaries that preserve counts, `SnapshotFindings`, and `Scorecard` but drop verbose fields such as `DataSourceCapabilities`, `AttackChains`, `RuleResults`, `Warnings`, and `LogAnalysisResult`. This bounds the on-disk file size without breaking diff comparisons or compliance trend charts.

A small `RuleCategoryResolver` helper centralizes rule-prefix parsing (e.g., `FW-002` → `FW`) and category-specific remediation-wisdom guidance text, keeping prefix knowledge in one place rather than duplicating it across the attack-chain mapper and wisdom analyzer.

### Conversation Awareness

The agent layer adds deterministic, LLM-free dialogue support through the `VulcansTrace.Linux.Agent.Dialogue` namespace:

- `DialogueContext` — tracks the current `ConversationTopic`, last `AgentIntent`, focused `Finding`, resolved entities (rule ID, category, session ID, ordinal), and a capped history of `DialogueTurn` records. It also provides `SnapshotState`/`RestoreState` so follow-up services that run nested audits can restore the full entity frame afterward.
- `EntityFrame` — shallow-copyable container for the focused rule ID, category, session IDs, ranked findings, last intent/topic, active remediation session, and the `CheckedCategories` coverage list. `DialogueManager.Resolve` snapshots it under the context lock before handing it to the resolver and inference engine.
- `EntityExtractor` — extracts rule IDs (`FW-001`), session IDs, ordinals (`1st`, `second one`), categories, and anaphora markers (`it`, `that`, `this one`) with word-boundary awareness and keyword ordering that lets specific terms (`ssh`, `filesystem`, `suid`) beat generic substrings (`service`, `file`).
- `AnaphoraResolver` — resolves pronouns and ordinals against a snapshot of `EntityFrame`. Ordinals map to ranked findings from the last audit; explicit rule IDs take precedence over pronouns. Session references (`verify it`, `check it`) only resolve when the topic is `Remediation` or a session exists.
- `IntentInferenceEngine` — re-evaluates parsed queries against `(prior topic, resolved entities, raw query)` and infers intents such as `FixFinding` after an explanation, `VerifyRemediation` after remediation, or `FilterCategory` after an audit. `BuildTarget` composes the final target from resolved references, parser output, and entity fallbacks, with explicit references taking precedence. It returns a confidence-weighted query and a flag indicating whether inference was applied.
- `ResponseTemplateProvider` — builds deterministic clarification prompts when a query remains ambiguous after inference.
- `DialogueManager` — orchestrates the flow: `QueryParser` → `AnaphoraResolver` → `IntentInferenceEngine`, then records the completed turn and can produce clarification prompts. It snapshots the entity frame under the context lock at resolve time.

`SecurityAgent.AskAsync` creates and updates `DialogueContext` through `DialogueManager` on every turn. The existing `AgentAuditState` type inherits from `DialogueContext` so existing follow-up services and tests remain compatible while gaining conversation-aware resolution. `SecurityAgent.ExplainFindingAsync` also updates the focused finding and topic so UI-selected-finding explanations support pronoun follow-ups.

### Cross-Session Memory

The agent layer now persists conversation context across process restarts through the `VulcansTrace.Linux.Agent.Memory` namespace:

- `IAgentMemoryStore` — abstracts asynchronous load/save of a lightweight `AgentMemorySnapshot`.
- `AgentMemorySnapshot` — captures last intent/topic, last audit intent, focused rule ID/category, active/last remediation session ID, the latest audit-history snapshot ID, up to 20 recent `DialogueTurn`s, the per-rule `RuleHistory` dictionary, and the `CheckedCategories` list. It intentionally does not duplicate full findings.
- `JsonFileAgentMemoryStore` — persists atomically to `~/.config/VulcansTrace/agent-memory.json` with string-enums for readability and an in-memory fallback on failure. Writes use async file I/O and are awaited before results return.
- `InMemoryAgentMemoryStore` — non-durable fallback.
- `SecurityAgent.RestoreMemorySnapshot` / `SaveMemorySnapshotAsync` — loads the snapshot on construction and saves after every turn. Restoration rehydrates a synthetic `AgentResult` from the referenced `AuditHistoryEntry` (including `CapabilityReport`, `RuleResults`, `Warnings`, `LogAnalysisResult`, `DataSourceCapabilities`, and `AttackChains`) so follow-ups like `what should I fix first?`, `fix it`, and `prove FW-002` work immediately after reopening the app. Slim history entries are not rehydrated because they lack the full detail needed for follow-ups; stale snapshots are ignored, corrupt fields are defaulted, and missing history entries clear stale focus state.

### Follow-Up Suggestions

Every `AgentResult` carries an `IReadOnlyList<SuggestedFollowUp>` produced by `AgentSuggestionProvider`. The provider is deterministic, LLM-free, and maps `(AgentResult, EntityFrame)` to contextual next queries such as `What should I fix first?`, `Fix it`, `Remediate it`, `Check drift`, and `Show baseline`. The Avalonia `AgentResultPresenter` attaches the suggestions to the first substantive agent message of a result (skipping info-only capability reports) and binds each chip to `AgentViewModel.ExecuteSuggestionAsync`. `ExecuteSuggestionAsync` routes by the suggestion's `Intent`: audit intents call `RunAuditAsync` directly, while non-audit intents execute the underlying query through `AskAsync`.

### Frame-Based NLU

The agent adds a second layer of deterministic entity extraction on top of the existing keyword parser:

- `IEntityExtractor` / `EntityExtractor` — extracts structured entities from raw user queries using regex and keyword matching. Supported entities include rule IDs (`FW-001`), categories (`firewall`, `ssh`), remediation session IDs, severity filters (`critical`, `high`), time windows (`last week`, `last 3 days`), remediation verbs (`fix`, `remediate`, `verify`, `explain`, `resume`), and ordinal references (`the third one`).
- `QueryEntityFrame` — immutable record that carries all extracted entities.
- `AgentQuery.Entities` — the parser attaches the entity frame to every parsed query.
- `DialogueManager.EnrichWithEntityFrame` — uses the frame to resolve obvious intent/reference cases before the full inference engine runs, e.g. a single rule ID plus `explain` becomes `ExplainFinding`, a session ID plus `verify` becomes `VerifyRemediation`.

This layer remains fully deterministic and introduces no external NLP/LLM dependencies.

### Per-Rule Memory

The agent persists per-rule history across process restarts:

- `IRuleMemoryRecorder` / `RuleMemoryRecorder` — records one severity snapshot per rule per audit, computes a trend (`New`, `Stable`, `Improving`, `Worsening`), and tracks `LastRemediationAttemptUtc` and `LastVerifiedFixedUtc`.
- `RuleMemoryEntry`, `RuleSeveritySnapshot`, `RuleStatusTrend` — domain types for the history model.
- `AgentMemorySnapshot.RuleHistory` — the memory snapshot now stores a dictionary of rule histories.
- `JsonFileAgentMemoryStore` — normalizes rule IDs to uppercase on load so case-insensitive lookups survive JSON round-trips.
- `SecurityAgent` — records history after every audit, stamps remediation-attempt timestamps when a guided remediation step reaches in-progress/completed/failed state, and stamps verified-fixed timestamps after session verification or targeted `VerifyFindingAsync`.
- Single-rule explanations use the same memory via `ExplanationDepthResolver` and `AdaptiveExplanationBuilder` to deepen explanation content when history warrants it.

### Category Coverage Tracking

The agent tracks which of the 17 targeted audit categories have been checked across turns and sessions, and surfaces blind spots after partial audits:

- `CategoryAuditEntry` — records a checked category and the UTC timestamp it was last audited.
- `CategoryCoverageRecorder` — updates coverage after every audit intent. A targeted intent marks one category; `FullAudit` marks all 17 categories. It also computes the unchecked subset for blind-spot reporting.
- `IntentCategoryMap` — central, single-source mapping between `AgentIntent` values and canonical category names (`Firewall`, `Network`, `Service`, `Port`, `SSH`, `FilePermission`, `FilesystemAudit`, `Kernel`, `UserAccount`, `Logging`, `CronJob`, `PackageVulnerability`, `Container`, `Kubernetes`, `ThreatIntel`, `Yara`, `ProcessRuntime`). This ensures the narrative composer, suggestion provider, and rule filter all agree on category boundaries.
- `EntityFrame.CheckedCategories` and `AgentMemorySnapshot.CheckedCategories` — carry the timestamped coverage list in memory and across restarts. `EntityFrame.Clear()` resets coverage when the user starts a fresh conversation.
- `NarrativeComposer.ComposeCoverage` — appends a **Coverage note** paragraph after targeted audits when unchecked categories remain. It lists the categories already audited, then up to three unchecked categories in catalog order with a `plus N more` suffix when applicable, e.g. "You've audited Firewall and SSH. You haven't checked Network, Service and Port, plus 12 more yet." The paragraph is suppressed when there is no prior coverage or when all categories are checked.
- `AgentSuggestionProvider.AddCoverageSuggestions` — emits one blind-spot follow-up chip for the first unchecked category after a targeted audit, using `IntentCategoryMap` to produce a user-friendly label and a query that routes back to the correct intent (e.g. `Check filesystem security`). The current category is excluded so the chip nudges toward a different area.
- Speculative-audit wrappers (`BaselineDriftService`, `GuidedRemediationService`, `AgentFollowUpService`) preserve cumulative coverage and rule history by calling `DialogueContext.RestoreState(..., preserveCoverage: true, preserveRuleHistory: true)`. This prevents drift checks, verification re-audits, and filter-category fallback audits from resetting long-horizon memory.
- `JsonFileAgentMemoryStore` reads coverage with `PropertyNameCaseInsensitive = true` so PascalCase legacy files and camelCase current files both round-trip correctly.

Coverage is cumulative memory, not transient display state. It survives `SnapshotState`/`RestoreState` cycles that are used to isolate speculative audits from the main conversation context.

### Cross-Category Posture Correlation

Beyond the temporal/network correlations produced by `TraceMapCorrelator`, the agent now detects dangerous combinations of static posture findings:

- `IPostureCorrelator` / `PostureCorrelator` — matches audit findings against a declarative registry of `PostureCorrelationPattern`s.
- `PostureCorrelation` — records the matched rule pair, combined severity, narrative, and finding IDs.
- Default patterns include `FW-002` + `SSH-002` (password SSH exposed to the internet), `FW-004` + `PORT-*` (exposed ports without a firewall), and `USER-001` + `SSH-002` (additional UID-0 accounts + password SSH).
- Correlations attach to `AgentResult.PostureCorrelations`; they do not create new findings and are deduplicated by `(PatternId, RuleIdA, RuleIdB)`.

### Narrative Composition Engine

The agent composes analyst-style prose from findings, correlations, attack chains, proactive alerts, system trajectory, remediation wisdom, and memory:

- `INarrativeComposer` / `NarrativeComposer` — builds a `Narrative` with summary, key findings, combined risk, trajectory, proactive alerts, attack chains, remediation patterns, continuity, next-steps, and (after partial audits) coverage-note paragraphs.
- `Narrative` — immutable record with `FullText`, per-paragraph accessors, and `SourceIds`.
- Every non-generic paragraph cites source IDs: rule IDs for findings, posture pattern IDs for correlations and attack chains, rule IDs for memory/trajectory/wisdom entries. The correlation paragraph always renders `[RuleIdA + RuleIdB]` so the traceability invariant holds even when a pattern template omits the IDs.
- `AgentResult.Narrative` — populated for audit results.
- `AgentResultPresenter` and the CLI render the narrative; the Avalonia UI uses a `MarkdownInlinesConverter` so `**bold**` and `*italic*` render with actual formatting. Evidence bundles include the narrative as `agent-narrative.md` and posture correlations as `posture-correlations.md` when present.

### Proactive, State-Triggered Suggestions

`AgentSuggestionProvider` now uses posture correlations and rule history to generate proactive follow-ups:

- When a correlated pair is detected, it suggests fixing both rules together.
- When a current rule has been stale or worsening for 7+ days, it suggests prioritizing it.
- After verification, if a correlated finding remains, it suggests fixing the related rule next.
- After a targeted audit with unchecked categories remaining, it suggests the first blind-spot category (e.g. `Check filesystem security`).

All suggestions still only reference findings that exist in the current result. The coverage chip is based on the cumulative category list rather than the current result's findings.

### Targeted Finding Verification

In addition to session-based verification, `SecurityAgent` exposes `VerifyFindingAsync(ruleId)`:

- Re-runs the last audit intent.
- Reports whether the specified rule is still failing.
- Stamps `LastVerifiedFixedUtc` when the rule no longer appears in the re-audit.

- `FindingAssemblyService` maps `RuleResult.MitreTechniques` to `Finding.MitreTechniques` so agent posture findings carry MITRE ATT&CK context through every export path.
- `RemediationMarkdownFormatter` renders exported session reports with a `## Notes` section that groups session notes and step notes (by rule ID), showing timestamps, text, and extracted evidence links. Remediation plan exports include an `## Impact Preview` block per section showing expected impact, rollback path, verification command, risk before/after, command count, rollback availability, restart impact, and lockout risk. Remediation sections now also carry `MitreTechniques` for threat-contextualized remediation planning.
- `RemediationImpactSimulator` analyzes each `RemediationSection` before it is displayed or executed, deriving risk metrics from the section's commands, safety classifications, and finding metadata. It detects restart impact (via `CommandSafety.ServiceRestart` and `systemctl restart/reload` patterns), lockout risk (via SSH config changes, iptables/UFW port-22 blocks, and default-deny rules), and produces a structured `RemediationImpactPreview` with all simulation fields. The simulator is called per-section by `RemediationPlanBuilder` with fault-isolating `try/catch` so a malformed section does not abort the entire plan.

The **Auto-Fix pipeline** extends the Security Agent to headless batch remediation:

1. `RemediationPlanBuilder` constructs a `RemediationPlan` from agent `Finding` records by parsing explanation templates into structured sections.
2. `CommandSafetyClassifier` analyzes each extracted command and labels it `ReadOnly`, `ConfigChange`, `ServiceRestart`, `PackageInstall`, `Destructive`, or `Unknown`.
3. `AutoFixPolicy` defines which safety classifications are permitted for automatic execution (configurable via `--allow-restart` and `--allow-packages`).
4. `RemediationPlanValidator` blocks sections where risky or unclassified commands lack explicit rollback guidance.
5. `RemediationImpactSimulator` enriches each section's `ImpactPreview` with derived risk metrics (risk before/after, command count, rollback availability, restart impact, lockout risk) before the plan is displayed or executed.
6. `RemediationExecutor` orchestrates the execution: backup commands first, then apply commands, then verification commands. If an apply command fails, rollback commands are executed automatically. Cancellation is checked before every command.
7. `ProcessRunner` executes shell commands via bash stdin (not `-c` argument wrapping) to avoid shell escaping vulnerabilities, with configurable timeout and cancellation support.
8. `RemediationConsoleFormatter` renders dry-run previews and execution results for CLI output, including all simulation fields.

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

1. `AuditSchedule` records define intent, cron expression, machine role, notification channel, enabled state, autonomous drift-response settings, signed-alert requirements, and human-approved remediation policy.
2. `IScheduleStore` persists schedules (`JsonFileScheduleStore` → `~/.config/VulcansTrace/schedules.json`); `InMemoryScheduleStore` provides a fallback.
3. `CrontabManager` reads/writes the system user crontab, using a unique marker prefix to identify VulcansTrace entries.
4. `CronExpressionValidator` validates 5-field cron syntax before persistence or crontab installation.
5. Scheduled audits run through the CLI (`vulcanstrace schedule run --id <id>`), which compares critical findings against the previous `AuditHistoryEntry` via fingerprint diffing and only notifies on new criticals.
6. When autonomous drift response is enabled, `AutonomousDriftResponder` compares the audit result against the intent-scoped baseline and sends a signed alert through the configured notification channel if drift meets the severity threshold.
7. `IAuditHistoryStore` persists lightweight audit snapshots (`JsonFileAuditHistoryStore` → `~/.config/VulcansTrace/audithistory.json`) for diff comparison and compliance trend calculation.
8. `VulcansTraceConfig` centralizes config-directory resolution so all file-backed stores respect an explicit directory, a process-wide override (set by `--config-dir`), or the default `XDG_CONFIG_HOME` / `~/.config` fallback.

Notification services are pluggable:

- `INotificationService` abstraction with `NotifyCriticalFindingsAsync` and `NotifySignedAlertAsync`.
- `SignedAlertMessage` carries the drift-alert payload plus `ScheduleId`, `Nonce`, and `Signature`.
- `SignedAlertVerifier` computes and verifies HMAC-SHA256 signatures over a stable canonical JSON form using constant-time comparison.
- `NotifySendNotificationService` shells out to `notify-send` for desktop alerts.
- `EmailNotificationService` sends SMTP email with TLS and credential support; it exposes an `IEmailTransport` seam for tests.
- `WebhookNotificationService` POSTs JSON payloads with retry logic for transient failures; it exposes an `HttpMessageHandler` seam for tests.
- All notification services catch exceptions and log to `stderr` so notification failures do not crash audits.

The human-approved remediation path for schedules:

1. `vulcanstrace schedule remediate --id <id>` (or the Avalonia **Remediate** button) runs the schedule's intent, builds a `RemediationPlan`, and applies the schedule's rule-prefix scope via `RemediationScopeFilter` before any command is executed.
2. `BuildScheduleRemediationPolicy` maps schedule flags (`AllowRemediationRestart`, `AllowRemediationPackages`) to an `AutoFixPolicy`.
3. The operator reviews the dry-run preview and confirms before `RemediationExecutor` executes permitted commands.
4. `RemediationScopeFilter` uses tokenized rule-ID matching so prefixes such as `FW` match only `FW-001`, not `FWO-002` or `KERN-001`.

## Key Domain Types

- `UnifiedEvent`: normalized schema for firewall logs, including Linux-specific fields.
- `AnalysisProfile`: intensity-tuned thresholds for each detector.
- `Finding`: immutable detector output with severity, detection confidence, evidence signals, time range, a stable fingerprint for tracking the same issue across audits, and grouping metadata (`GroupedCount`, `RepresentativeTargets`, `RiskDrivers`) when produced by the shared noise-budget pipeline.
- `AnalysisResult`: complete analysis output with entries, findings, warnings, and optional agent data-source capability context.
- `TraceMapResult`: container for findings and their directed correlation edges (`CorrelationEdge`), produced by `TraceMapCorrelator`.
- `CorrelationEdge`: directed edge between two findings (`FromFindingId`, `ToFindingId`, `CorrelationType`, `Narrative`, `CorrelationConfidence`).
- `CorrelationType`: `EscalatesTo`, `SameHost`, or `TemporalSequence`.
- `CorrelationConfidence`: `Low`, `Medium`, or `High`, derived from time gap between findings.
- `DetectionConfidence`: five-level enum (`Unknown`, `Low`, `Medium`, `High`, `Confirmed`) indicating how strongly the available evidence supports the finding.
- `EvidenceSignal`: immutable record (`Name`, `Source`, `Explanation`) representing a single piece of supporting evidence. Sources include `Behavior` (detector-derived) and `ThreatIntel` (IOC-matched).
- `FindingConfidenceCalculator`: engine-side calculator that maps a finding's evidence signals to a `DetectionConfidence` level. Rules: zero signals → `Unknown`; one → `Low`; two → `Medium`; three or more → `High`; simultaneous `ThreatIntel` + `Behavior` → `Confirmed`.
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
- `IocEntry`: immutable IOC record (`Type`, `Value`, `ThreatScore`, `Source`, `ImportedAtUtc`).
- `CriticalChain`: record representing a detected critical attack chain (Beaconing → LateralMovement → PrivilegeEscalation) on a single host, with chronologically sorted `FindingIds`.
- `AgentQuery`: structured user request containing `AgentIntent`, optional target reference, confidence, ambiguity flag, the original raw query text for inference reuse, and a `QueryEntityFrame` with extracted entities.
- `QueryEntityFrame`: deterministic entity frame carrying rule IDs, categories, session IDs, severity filters, time windows, remediation verbs, ordinals, and tokens.
- `SuggestedFollowUp`: a contextual next-step suggestion with a user-facing label, the query to execute, and the mapped `AgentIntent`.
- `CategoryAuditEntry`: timestamped record that a specific audit category was checked.
- `CategoryCoverageRecorder`: records `CheckedCategories` after each audit and computes the unchecked subset for blind-spot surfacing.
- `IntentCategoryMap`: central mapping between `AgentIntent` values and canonical category names, plus reverse lookups and suggestion text for coverage chips.
- `PostureCorrelation` / `PostureCorrelationPattern`: cross-category posture correlation records and declarative pattern definitions.
- `AttackChain` / `AttackChainLink`: ordered kill-chain path built from posture-backed staged findings, carrying rule IDs, MITRE technique IDs, and source posture pattern IDs.
- `SystemTrajectory`: system-level trend direction derived from aggregated per-rule trends and verified-fixed absent rules, with weighted severity delta and example rule IDs.
- `ProactiveAlert`: a finding that returned after a previous verified fix, citing the rule ID, last verified-fixed timestamp, and category-specific regression guidance.
- `RemediationWisdom`: deterministic guidance for rules with repeated remediation-recurrence cycles.
- `RuleMemoryEntry` / `RuleSeveritySnapshot` / `RuleStatusTrend` / `RemediationCycle`: per-rule history model; `RemediationCycle` records one attempt → verified-fixed → returned loop and can remain pending between phases.
- `ExplanationDepth`: enum (`Standard`, `Familiar`, `Recurring`, `Escalating`) that selects how much context a single-rule explanation includes.
- `ExplanationDepthResolver`: deterministic resolver that maps a `RuleMemoryEntry` to an `ExplanationDepth` from history length, closed remediation cycle count, and trend.
- `AdaptiveExplanationBuilder`: appends history, root-cause, and escalation paragraphs to a single-rule explanation based on the resolved depth.
- `Narrative`: composed multi-paragraph response with traceable source IDs.
- `IAgentMemoryStore` / `AgentMemorySnapshot`: persistence contract and lightweight snapshot for cross-session conversation memory.
- `DialogueContext`: in-memory conversation state including topic, entities, focused finding, a capped history of `DialogueTurn` records, and `SnapshotState`/`RestoreState` for nested-audit save/restore. It also supports `RestoreHistory` to rehydrate recent turns from a persisted snapshot.
- `EntityFrame`: shallow-copyable container for the focused rule ID, category, session IDs, ranked findings, last intent/topic, active remediation session, and the `CheckedCategories` coverage list.
- `ReferenceResolution`: result of anaphora resolution with flags for anaphora presence, resolved rule ID, category, session ID, ordinal, and finding.
- `ConversationTopic`: enum (`Unknown`, `Audit`, `Explanation`, `Remediation`, `Help`, `Comparison`, `Drift`) used to gate intent inference.
- `CountermeasureCommand`: record representing an active defense command (`IptablesDrop` or `AuditdMonitor`) with apply command, rollback command, safety classification, and target host.
- `CountermeasureType`: enum discriminating `IptablesDrop` and `AuditdMonitor` countermeasure kinds.
- `FileHashEntry`: scanner output pairing a file path with its SHA-256 hash (`Path`, `Hash`, `Algorithm`).
- `YaraMatchEntry`: scanner output for a YARA rule match, including the target path, target kind, matching rule identifier, optional process ID, and optional match description.
- `SignedAlertMessage`: signed drift-alert payload carrying title, body, schedule identity, nonce, severity counts, rule IDs, attack chains, proactive alerts, remediation summary, timestamp, and signature.
- `SignedAlertVerifier`: HMAC-SHA256 signer/verifier for `SignedAlertMessage` with constant-time comparison and a stable canonical JSON form.
- `RemediationScopeFilter`: tokenized rule-prefix filter shared between alert composition and remediation execution.
- `VulcansTraceConfig`: centralized config-directory resolver used by all file-backed stores.

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
- `IocEntry` — immutable IOC record with `Type`, `Value`, `ThreatScore`, `Source`, `ImportedAtUtc`.
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
