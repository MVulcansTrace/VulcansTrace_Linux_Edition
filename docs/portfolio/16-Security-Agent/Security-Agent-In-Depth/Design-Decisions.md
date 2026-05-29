# Design Decisions

## Deterministic First

The agent is intentionally rule-based. That choice keeps the first version auditable: every finding comes from a scanner result, a rule, and an explanation template. For a security tool, this matters more than sounding conversational. A deterministic v1 also gives later AI-style features a stable base to summarize, prioritize, or explain without owning the source of truth.

## Separate Scanners From Rules

Scanners collect facts. Rules interpret those facts. This split keeps host collection logic out of policy decisions:

- `FirewallScanner` knows how to collect and parse iptables/nftables output.
- `PortScanner` knows how to collect listening sockets.
- `ServiceScanner` knows how to read running systemd services.
- `NetworkScanner` knows how to collect interfaces, routes, and connections.
- Rules only consume `ScanData`.

That means rules can be tested with synthetic `ScanData` without depending on the host machine. It also means scanner parsers can evolve without rewriting the rule layer.

## Carry Query Structure Through The Pipeline

`QueryParser` returns `AgentQuery`, not just `AgentIntent`. That lets the parser preserve a target reference such as `FW-001`, `PORT-002`, `firewall`, or `ssh` for later resolution. The agent can then decide whether to explain a cached finding, run one matching rule, or return guidance.

## Cache Rule IDs With Findings

`Finding` now carries an optional `RuleId` for agent-generated findings while remaining compatible with engine findings that do not have rule IDs. The agent also keeps a private history of `(RuleId, Finding)` pairs after audits. This makes follow-up prompts such as `explain FW-001` stable and lets evidence exports preserve the rule identifier without forcing the log-analysis engine to invent one.

## Thread-Safe Aggregation

The agent runs scanners concurrently, so `ScanDataBuilder` protects mutation with a lock and returns immutable array snapshots in `Build()`. This keeps the scanner phase fast while avoiding races when different scanners add ports, services, routes, warnings, and firewall state.

## Command Execution With Explicit Exit Status

Scanner command helpers return stdout, stderr, and success status. They read stdout and stderr concurrently to avoid process deadlocks when a command writes enough stderr output to fill a pipe. Scanner failures are converted into warnings so a missing command or permission issue does not crash the whole audit.

## Explain With Templates

`ExplanationProvider` loads embedded markdown templates and replaces variables such as port, service, source, process, or policy. It also parses those templates into structured sections for what was found, why it matters, how to verify, suggested next action, confidence, and caveats. This keeps explanation language editable without changing rule code and avoids mixing detection logic with user-facing prose.

Copyable commands are intentionally scoped to the `How to verify` section. Suggested remediation commands remain visible in explanations and remediation preview exports, but they are not labeled as verification steps and are not executed by the application. Extracted commands receive a keyword-based safety label so analysts can quickly distinguish read-only checks from configuration changes, service restarts, package operations, destructive commands, or unclassified commands.

## Time-Bound Suppressions

Accepted-risk suppressions are exact rule-ID/target matches with explicit durations: 7 days, 30 days, 90 days, or permanent. Expired entries are ignored by lookup immediately, but remain visible in the review queue for 30 days before audit-time pruning removes them. This keeps the feature useful for intentional exceptions without allowing temporary risk acceptance to silently become permanent or hiding recently expired decisions before an analyst can review them.

## Preserve Existing Analysis Contracts

`AgentReportGenerator` converts `AgentResult` into the same `AnalysisResult` type used by the log engine. That keeps the evidence pipeline, exports, and UI concepts aligned. Agent findings are not a parallel reporting universe; they can participate in the existing VulcansTrace workflow, including CSV, JSON, Markdown, HTML, and STIX evidence exports with agent rule IDs preserved when present. When active suppressions exist, evidence exports include suppression notes in Markdown/HTML and a `suppressions.csv` sidecar in the signed ZIP.

Agent audit results are also loaded into the shared findings grid. That makes the same selection, explanation, accepted-risk suppression, and evidence-export affordances work for both pasted-log analysis and live posture audits.

## UI As A Thin Control Shell

The Avalonia agent panel delegates behavior to `AgentViewModel`, which delegates security work to `IAgent`. This keeps the UI responsible for messages, commands, cancellation, grouped rendering, filtering, quick actions, privilege warnings, suppression review refreshes, and bindings, while the agent project owns security logic. For selected-finding explanations, the UI provides the currently selected `Finding` through a small provider function and calls `ExplainFindingAsync` directly.

## Current Tradeoffs

- Keyword intent parsing is simple and predictable but not deeply semantic.
- Command-output parsers are practical for v1 and now have realistic fixture coverage, but more distro variants should be added over time.
- Direct selected-finding explanations summarize existing finding details rather than performing deeper multi-turn reasoning.
- Rules favor actionable posture checks, which can create findings that need analyst judgment rather than direct incident conclusions.
