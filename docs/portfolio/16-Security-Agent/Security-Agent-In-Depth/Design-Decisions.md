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

`Finding` is a shared core type and does not contain an agent rule ID. The agent therefore keeps a private history of `(RuleId, Finding)` pairs after audits. This makes follow-up prompts such as `explain FW-001` stable without depending on the rule ID appearing in rendered markdown details.

## Thread-Safe Aggregation

The agent runs scanners concurrently, so `ScanDataBuilder` protects mutation with a lock and returns immutable array snapshots in `Build()`. This keeps the scanner phase fast while avoiding races when different scanners add ports, services, routes, warnings, and firewall state.

## Command Execution With Explicit Exit Status

Scanner command helpers return stdout, stderr, and success status. They read stdout and stderr concurrently to avoid process deadlocks when a command writes enough stderr output to fill a pipe. Scanner failures are converted into warnings so a missing command or permission issue does not crash the whole audit.

## Explain With Templates

`ExplanationProvider` loads embedded markdown templates and replaces variables such as port, service, source, process, or policy. This keeps explanation language editable without changing rule code. It also avoids mixing detection logic with user-facing prose.

## Preserve Existing Analysis Contracts

`AgentReportGenerator` converts `AgentResult` into the same `AnalysisResult` type used by the log engine. That keeps the evidence pipeline, exports, and UI concepts aligned. Agent findings are not a parallel reporting universe; they can participate in the existing VulcansTrace workflow.

## UI As A Thin Chat Shell

The Avalonia agent panel delegates behavior to `AgentViewModel`, which delegates security work to `IAgent`. This keeps the UI responsible for messages, commands, cancellation, and bindings, while the agent project owns security logic. For selected-finding explanations, the UI provides the currently selected `Finding` through a small provider function and calls `ExplainFindingAsync` directly.

## Current Tradeoffs

- Keyword intent parsing is simple and predictable but not deeply semantic.
- Command-output parsers are practical for v1 but need fixture coverage across distributions.
- Direct selected-finding explanations summarize existing finding details rather than performing deeper multi-turn reasoning.
- Rules favor actionable posture checks, which can create findings that need analyst judgment rather than direct incident conclusions.
