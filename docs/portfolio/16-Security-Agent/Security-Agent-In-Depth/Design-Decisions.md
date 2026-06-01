# Design Decisions

## Deterministic First

The agent is intentionally rule-based. That choice keeps the first version auditable: every finding comes from a scanner result, a rule, and an explanation template. For a security tool, this matters more than sounding conversational. A deterministic v1 also gives later AI-style features a stable base to summarize, prioritize, or explain without owning the source of truth.

## Separate Scanners From Rules

Scanners collect facts. Rules interpret those facts. This split keeps host collection logic out of policy decisions:

- `FirewallScanner` knows how to collect and parse iptables/nftables output.
- `PortScanner` knows how to collect listening sockets.
- `ServiceScanner` knows how to read running systemd services.
- `NetworkScanner` knows how to collect interfaces, routes, and connections.
- `FilePermissionScanner` knows how to read permission bits and ownership via `stat`.
- `FilesystemAuditScanner` knows how to run targeted `find` commands for world-writable files, SUID/SGID binaries, unowned files, sticky-bit checks, and `/tmp` mount options.
- `KernelHardeningScanner` knows how to read `/proc/sys` parameters and Secure Boot state.
- `UserAccountScanner` knows how to read `/etc/passwd`, `/etc/shadow`, `/etc/login.defs`, and PAM password-stack configuration.
- `LoggingAuditScanner` knows how to check logging service status, read auditd rules, verify logrotate configuration, and detect central forwarding targets.
- Rules only consume `ScanData`.

That means rules can be tested with synthetic `ScanData` without depending on the host machine. It also means scanner parsers can evolve without rewriting the rule layer.

## Carry Query Structure Through The Pipeline

`QueryParser` returns `AgentQuery`, not just `AgentIntent`. That lets the parser preserve a target reference such as `FW-001`, `PORT-002`, `firewall`, or `ssh` for later resolution. The agent can then decide whether to explain a cached finding, run one matching rule, or return guidance.

## Cache Rule IDs With Findings

`Finding` now carries an optional `RuleId` for agent-generated findings while remaining compatible with engine findings that do not have rule IDs. The agent also keeps a private history of `(RuleId, Finding)` pairs after audits. This makes follow-up prompts such as `explain FW-001` stable and lets evidence exports preserve the rule identifier without forcing the log-analysis engine to invent one.

## Track Stable Finding Identity

`Finding.Fingerprint` gives the agent a stable identity key for the underlying issue. It is derived from rule ID, category, source host, and target, while excluding timestamps, descriptions, details, and severity. That lets audit diffs report a finding as worsened or improved when severity changes instead of treating it as resolved plus new.

Audit history stores the fingerprint with each snapshot finding. The diff calculator matches by fingerprint when both snapshots have one, and falls back to rule ID plus target when comparing against older history entries created before fingerprints existed.

## Thread-Safe Aggregation

The agent runs scanners concurrently, so `ScanDataBuilder` protects mutation with a lock and returns immutable array snapshots in `Build()`. This keeps the scanner phase fast while avoiding races when different scanners add ports, services, routes, warnings, and firewall state.

## Report Data-Source Capability Separately

Scanner warnings explain what went wrong; data-source capabilities explain what evidence was actually available. Each scanner records command visibility as available, unavailable, permission-limited, or unknown. `SecurityAgent` turns those entries into a deterministic report so the UI and exported evidence can show whether posture conclusions came from full scanner visibility or from a limited local environment.

Unknown is used when a fallback command was intentionally not checked because a preferred source already returned usable data. This avoids implying that a command is missing when the scanner simply did not need it.

## Command Execution With Explicit Exit Status

Scanner command helpers return stdout, stderr, and success status. They read stdout and stderr concurrently to avoid process deadlocks when a command writes enough stderr output to fill a pipe. Scanner failures are converted into warnings so a missing command or permission issue does not crash the whole audit.

## Explain With Templates

`ExplanationProvider` loads embedded markdown templates and replaces variables such as port, service, source, process, or policy. It also parses those templates into structured sections for what was found, why it matters, how to verify, preconditions, backup commands, suggested next action, rollback commands, confidence, and caveats. This keeps explanation language editable without changing rule code and avoids mixing detection logic with user-facing prose.

Copyable commands are intentionally scoped to the `How to verify` section. Suggested remediation commands remain visible in explanations and guarded remediation preview exports, but they are not labeled as verification steps and are not executed by the application. Extracted commands receive a keyword-based safety label so analysts can quickly distinguish read-only checks from configuration changes, service restarts, package operations, destructive commands, or unclassified commands.

## Tune Rules With Local Context

The same open port can mean different things on a laptop, a bastion host, a lab VM, or a development machine. `MachineRole`, `RulePolicy`, and `IContextualRule` keep that local context explicit instead of baking one global standard into every rule.

The default provider supplies conservative built-in role defaults for selected rules. The JSON policy store then overrides those defaults from `~/.config/VulcansTrace/policy.json`, merging user parameters over built-in parameters so local policy can adjust only the part it owns. Disabled rules are skipped, auto-pass policies turn known-acceptable failures into passed results, and severity overrides are applied before findings are created.

## Time-Bound, Fingerprint-Scoped Suppressions

Accepted-risk suppressions use finding fingerprints when available, with legacy rule-ID/target matching for entries created before fingerprints existed. A fingerprinted suppression only matches that exact finding identity, so suppressing one accepted exposure does not accidentally hide a different finding with the same rule and target text. Durations are explicit: 7 days, 30 days, 90 days, or permanent. Expired entries are ignored by lookup immediately, but remain visible in the review queue for 30 days before audit-time pruning removes them. This keeps the feature useful for intentional exceptions without allowing temporary risk acceptance to silently become permanent or hiding recently expired decisions before an analyst can review them.

## Preserve Existing Analysis Contracts

`AgentReportGenerator` converts `AgentResult` into the same `AnalysisResult` type used by the log engine. That keeps the evidence pipeline, exports, and UI concepts aligned. Agent findings are not a parallel reporting universe; they can participate in the existing VulcansTrace workflow, including CSV, JSON, Markdown, HTML, and STIX evidence exports with agent rule IDs, fingerprints, and capability reports preserved when present. When active suppressions exist, evidence exports include suppression notes in Markdown/HTML and a `suppressions.csv` sidecar in the signed ZIP.

Agent audit results are also loaded into the shared findings grid. That makes the same selection, explanation, accepted-risk suppression, and evidence-export affordances work for both pasted-log analysis and live posture audits.

## UI As A Thin Control Shell

The Avalonia agent panel delegates behavior to `AgentViewModel`, which delegates security work to `IAgent`. This keeps the UI responsible for messages, commands, cancellation, grouped rendering, filtering, quick actions, privilege warnings, suppression review refreshes, and bindings, while the agent project owns security logic. For selected-finding explanations, the UI provides the currently selected `Finding` through a small provider function and calls `ExplainFindingAsync` directly.

## Follow-Up Questions Without Re-Scanning

Follow-up intents (`ShowChanges`, `ExplainCritical`, `FilterCategory`, `PrioritizeRemediation`, `ListSuppressed`) operate on the cached `_lastResult` instead of re-running scanners. This keeps them fast and deterministic. `ShowChanges` compares `_lastResult` against `IAuditHistoryStore`, skipping the history entry that matches the current result's timestamp so it does not diff an audit against itself. `FilterCategory` falls back to a fresh targeted audit only when no prior context exists, saves and restores `_lastResult` around the fallback so it does not corrupt the user's context, and returns the result with `Intent = FilterCategory` so the UI does not misinterpret it as a standalone audit.

## Configuration Baselines And Drift Detection

Baselines are user-designated "known good" snapshots, separate from the automatic rolling audit history. This separation matters because history is an automatic log with pruning, while baselines are curated, intent-scoped, and long-lived.

- **Intent-scoped baselines** — one active baseline per `AgentIntent` (FullAudit, FirewallCheck, SSHCheck, etc.). This lets a user baseline their firewall posture separately from their full system posture.
- **Named baselines** — each baseline has a user-friendly name and stores both lightweight `AuditSnapshotFinding` records for diff calculations and the original `Finding` objects for lossless display in `ShowBaseline`.
- **Separate storage** — `IBaselineStore` and `JsonFileBaselineStore` follow the same persistence pattern as audit history and suppressions, writing to `~/.config/VulcansTrace/baselines.json`.
- **Drift via diff reuse** — `CheckDrift` re-runs the target audit and compares the live result against the active baseline using `AuditDiffCalculator`. The diff semantics (new, resolved, worsened, improved, unchanged) map directly to drift semantics, so the same narrative and summary experience applies.
- **Context preservation** — `RunDriftCheckAsync` saves and restores `_lastResult` around the inner `RunAuditAsync` call so drift checks do not corrupt the user's previous audit context.
- **Audit-intent isolation** — `_lastAuditIntent` tracks only actual audit intents, separate from `_lastResult.Intent`. This prevents a `SetBaseline` after `CheckDrift` from scoping the baseline to `CheckDrift` instead of the original audit intent.

## Dual-Layer CIS Benchmark Mapping

**Decision:** Every rule carries both a CIS Controls v8 organizational mapping and a CIS Ubuntu 24.04 LTS Benchmark technical mapping.

**Rationale:**

- CIS Controls v8 (`CIS 4.5`, `CIS 5.4`, etc.) answers "what control area does this finding violate?" for executives and auditors.
- The Ubuntu benchmark (`5.2.7 Ensure SSH root login is disabled`) answers "exactly which scored configuration item failed?" for Linux administrators and compliance reviewers.
- A Linux security tool that only maps to organizational controls looks generic. Adding the specific benchmark section makes the mapping credible and actionable.
- The `BenchmarkReference` field is optional on `CisBenchmarkMapping`, so rules without a clean 1:1 benchmark match can still carry the Controls v8 mapping alone.

**Trade-off:** Benchmark section numbers drift across distro versions. The current references target CIS Ubuntu 24.04 LTS; future distro support may need versioned benchmark references or a mapping table per distro.

**Deduplication choice:** HTML and Markdown compliance-context sections previously grouped by `ControlId` and took `First()`, which hid differing `WhyItMatters` text when multiple rules mapped to the same control (e.g., all five firewall rules map to `CIS 4.5`). The dedup was changed to `Distinct()` on the full record so every unique rationale and benchmark reference is preserved.

## Interactive Remediation: Guided, Not Automated

**Decision:** The agent can guide remediation for a specific finding (`fix FW-001`), and the CLI can execute safe fixes in batch mode (`--auto-fix`), but both are gated by explicit safety policies and never run destructive or unclassified commands without operator consent.

**Rationale:**

- Security tools that silently auto-remediate can break production access, drop SSH sessions, or disable services unexpectedly.
- A guided, step-by-step UX with explicit preconditions, backup commands, apply commands, rollback commands, and verification commands gives the operator full control.
- Each command is labeled with the existing `CommandSafety` classification (`ReadOnly`, `ConfigChange`, `Destructive`, etc.) and structural badges (`SUDO`, `CHAIN`, `PIPE`, etc.) so the operator knows the blast radius before copying a command.
- `RemediationPlanValidator` blocks the entire flow if risky or unclassified commands lack explicit rollback guidance. This prevents the UI from presenting a "safe" fix that has no undo path.
- The same `RemediationPlan` and `RemediationPlanBuilder` infrastructure used for the bulk export path is reused for both interactive and batch remediation, so all paths benefit from the same safety guardrails.
- Batch auto-fix (`--auto-fix`) extends the interactive model to headless use cases:
  - `AutoFixPolicy` defines what is permitted (`ReadOnly`, `ConfigChange`, and optionally `ServiceRestart`/`PackageInstall`).
  - Destructive and unclassified commands are never auto-executed.
  - Backup commands run before apply; backup failures abort the section.
  - Apply failures trigger automatic rollback for that section.
  - `--dry-run` previews the plan without executing anything.
  - `--yes` skips confirmation; without it, the operator must type `yes`.
  - Commands are fed to bash via stdin to avoid shell escaping bugs.

**Trade-off:** The interactive UX requires the operator to manually copy and run each command. This is slower than one-click auto-fix, but it preserves accountability and prevents accidental outages. The batch CLI path trades some control for automation, but only within the narrow safety envelope defined by `AutoFixPolicy` and `RemediationPlanValidator`.

## Not-Applicable Results For Hardware-Dependent Checks

**Decision:** Rules that depend on hardware features the system may not have (e.g., UEFI Secure Boot on BIOS systems) return `RuleStatus.NotApplicable` instead of Pass or Fail.

**Rationale:**

- Returning Pass would mislead the user into thinking they passed a check that does not apply to their system.
- Returning Fail would create false positives on correctly configured BIOS systems.
- NotApplicable is excluded from passed/failed counts but included in the total rule count, and the audit summary explicitly notes how many checks were not applicable. This keeps the user informed without distorting pass/fail metrics.

**Trade-off:** UI coverage grids must account for NotApplicable as a fifth bucket alongside Passed, Failed, Suppressed, and Crashed.

## CIS Compliance Scorecard Design

**Decision:** Compute a formal compliance scorecard from rule results with per-family Pass/Warn/Fail, an overall rule-level percentage, and a trend over time.

**Rationale:**

- Managers and auditors need a 10-second readable summary of compliance posture, not a raw list of findings.
- A scorecard with per-family breakdown shows which control areas (e.g., Firewall, SSH, Kernel) need attention.
- Trend visualization makes improvement or regression visible over repeated audits.
- Evidence bundles should include manager-friendly reports (`compliance-scorecard.html` and `compliance-scorecard.md`) alongside technical findings.

**Thresholds:**
- Pass ≥90% (`ComplianceScorecard.PassThreshold`)
- Warn ≥80% (`ComplianceScorecard.WarnThreshold`)
- Fail <80% or any crashed rule

**Scoring rules:**
- `NotApplicable` rules are excluded from scoring entirely (they distort neither family nor overall metrics).
- `Suppressed` rules are excluded from the applicable denominator (suppression is a deliberate user decision, not a compliance gap).
- Multi-family rules count once per family for family scores, but the overall score is computed at the rule level to prevent double-counting.
- Families with only `NotApplicable` rules are filtered out (no noise entries with 0 total).

**Trend:**
- Uses `IAuditHistoryStore` (last 10 entries, capped to prevent unbounded growth).
- Compares current score against the most recent history entry for direction (Improving, Declining, Stable).

**Trade-off:** The scorecard is a management abstraction, not a substitute for individual finding review. A family can Pass at 90% while still having failed rules that need remediation.

## Current Tradeoffs

- Keyword intent parsing is simple and predictable but not deeply semantic.
- Command-output parsers are practical for v1 and now have realistic fixture coverage, but more distro variants should be added over time.
- Follow-up questions are deterministic transformations of existing data, not open-ended conversational reasoning.
- Rules favor actionable posture checks, which can create findings that need analyst judgment rather than direct incident conclusions.
