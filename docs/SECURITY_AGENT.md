# Security Agent

The Security Agent is a local, rule-based Linux security assistant built into VulcansTrace Linux Edition. It answers plain-English security questions, scans live host state, evaluates defensive posture rules, explains findings, and can include pasted firewall logs in the same analysis workflow.

The agent is intentionally deterministic. It does not call an external LLM or send system data to a service. Its value comes from a predictable pipeline: query parsing, local scanners, rule evaluation, explanation templates, and compatibility with the existing VulcansTrace `AnalysisResult` and evidence pipeline.

## What It Can Answer

The query parser maps natural-language prompts to structured intents:

| Example prompt | Intent | Result |
| --- | --- | --- |
| `Is my system secure?` | `FullAudit` | Runs all agent rule categories |
| `Run a full audit` | `FullAudit` | Runs all agent rule categories |
| `Check my firewall` | `FirewallCheck` | Runs firewall posture rules |
| `How's my iptables?` | `FirewallCheck` | Runs firewall posture rules |
| `What ports are open?` | `PortCheck` | Reviews listening ports and exposure |
| `What services are running?` | `ServiceCheck` | Reviews running services |
| `Who am I talking to?` | `NetworkCheck` | Reviews routes, interfaces, and connections |
| `Explain FW-001` | `ExplainFinding` | Explains a cached finding by rule ID, or runs that single rule if needed |
| `Explain this finding` | `ExplainFinding` | Explains the currently selected UI finding when one is selected |
| `Help` | `Help` | Returns supported agent capabilities |

## Data Sources

The agent reads local host state using common Linux tools:

| Scanner | Commands | Purpose |
| --- | --- | --- |
| `FirewallScanner` | `iptables -L -n -v`, fallback `nft list ruleset` | Reads firewall posture and rule text |
| `PortScanner` | `ss -tulnp`, fallback `netstat -tulnp` | Finds listening TCP/UDP ports and owning processes when visible |
| `ServiceScanner` | `systemctl list-units --type=service --state=running --no-pager --no-legend` | Finds running systemd services |
| `NetworkScanner` | `ip addr`, `ip route`, `ss -tunap` | Reads interfaces, routes, and active connections |

Scanner failures are reported as warnings instead of crashing the agent. Some commands may expose less detail without elevated privileges, especially process names and firewall rules.

## Rule Coverage

### Firewall

- Firewall should be active.
- INPUT default policy should not be broadly permissive.
- SSH should not be exposed to all sources without restriction.
- Established/related connection state tracking should be present.
- ICMP should not be blanket-accepted without review.

### Ports

- SSH listening on port 22 is reported as informational.
- Services listening on all interfaces are reviewed.
- Common database ports exposed on all interfaces are Critical.
- Unknown high-port listeners without process names are reported for review.

### Services

- Telnet should not be running.
- FTP should not be running when SFTP/SSH alternatives exist.
- SSH presence is checked for expected remote administration.
- Legacy r-services are flagged.
- Common unnecessary services such as CUPS, Avahi, Bluetooth, NFS, RPC, SMB, and NetBIOS are reviewed.

### Network

- A default route should exist.
- Suspicious established outbound connections to high-risk ports are flagged.
- At least one interface should be up.
- Services intended for loopback should not also listen on all interfaces.

## How The Pipeline Works

1. `QueryParser` converts the user query into an `AgentQuery` containing an `AgentIntent` and optional target reference.
2. `SecurityAgent` runs the required scanners with cancellation support.
3. `ScanDataBuilder` collects scanner output into a thread-safe snapshot.
4. Rules matching the requested intent evaluate the snapshot.
5. Failed rules become `Finding` records.
6. `ExplanationProvider` fills markdown templates for each finding and parses them into structured explanation sections.
7. `SecurityAgent` remembers generated findings with their originating rule IDs so follow-up questions like `explain FW-001` can resolve without relying on text matching.
8. If raw log text is available, `SentryAnalyzer` can add log-derived findings.
9. Suppressions expired longer than the 30-day review retention window are pruned, active exact-match suppressions are applied, and rule pass/fail/suppressed counts are added to `AgentResult`.
10. `AgentReportGenerator` can merge agent findings and log findings into an `AnalysisResult`; exported CSV, JSON, Markdown, HTML, and STIX evidence preserves agent rule IDs when present and can include active suppression notes.

## Explanation Behavior

The agent supports three explanation paths:

- **Selected finding:** if the user selects a finding in the UI and asks `explain this finding`, `AgentViewModel` calls `ExplainFindingAsync` directly without re-scanning.
- **Previous agent finding:** after an audit, references such as `explain FW-001`, `explain firewall`, or `explain SSH` are resolved against cached agent findings.
- **Known rule ID with no cached finding:** if a rule ID is recognized but no previous finding is available, the agent runs that single rule and explains the result if it fails.

When no selected finding or target reference is available, the agent returns guidance instead of running an unrelated full audit.

Explanations are rendered as structured sections: what was found, why it matters, how to verify, suggested next action, confidence, and caveats. The UI extracts copyable commands only from the verification section and labels them with a heuristic safety classification. Suggested action commands are kept in the explanation/remediation preview path, safety-labeled in exported remediation plans, and never applied automatically.

## UI Integration

The Avalonia application exposes the agent in a collapsible Security Agent panel. The panel supports:

- Chat-style natural-language questions.
- Quick-action buttons for full audit, firewall, ports, services, network, selected-finding explanation, and audit export.
- In-flight query cancellation.
- Agent findings grouped by category with compact severity summaries.
- Chat filters for severity and category that hide/show finding groups without changing the underlying audit result.
- A Coverage tab after agent audits with totals and category breakdowns for passed, active failed, suppressed, and crashed rule checks.
- Two-way selection tracking from the findings grid for selected-finding explanations; the Explain Selected action is only enabled when a finding is selected.
- Agent audit results are loaded into the shared findings grid so they can be selected, explained, exported, or suppressed.
- An elevated-privilege warning banner when scanner output indicates permission-limited visibility.
- Audit history persisted to the user config directory when available, capped at 50 lightweight snapshots by default, with compare-last-two, selectable before/after comparison, deterministic narrative diff summaries, and exported-state tracking after successful evidence export. If persistence fails, the UI reports that history is session-only.
- Accept Risk suppressions by rule ID and target, with 7-day, 30-day, 90-day, or permanent durations. Expired suppressions stop applying immediately, remain in the review queue for 30 days, and are pruned after that retention window. Suppressions are persisted to the user config directory when available; if persistence fails, the UI reports that suppressions are session-only.
- A Suppressions tab with friendly filter labels, review counts, status badges, and row actions to renew, convert duration, edit reason, or remove suppressions.
- Export Audit support that reuses the shared evidence export flow for the latest agent audit and includes active suppression notes when present.
- Export Remediation support that writes a review-only markdown plan with safety notes, rollback hints, and verification commands.
- Automatic sharing of the main log input with the agent so pasted firewall logs can be included in agent analysis.

## Privacy And Safety

- The agent is local-only.
- It does not make network calls for analysis.
- It reads host state through local Linux commands.
- It does not modify firewall rules, services, network interfaces, routes, or files.
- It reports warnings when data cannot be collected.

## Current Limitations

- It is a deterministic rule-based assistant, not an LLM-backed conversational system.
- Scanner parsers are pragmatic and command-output based, so unusual distro output may need parser tests and adjustments.
- Some findings are posture checks rather than proof of compromise.
- Process names and firewall details may require elevated privileges depending on the host.
- Direct selected-finding explanations summarize the existing finding details; deeper conversational follow-up is not implemented yet.
- Suppressions are exact rule-ID/target matches, so intentional target text changes can require accepting the risk again.
- Command safety labels use conservative keyword heuristics. Unknown means "not classified," not "safe."

## Roadmap

- Add richer follow-up explanation flows that can compare related findings and suggest next triage steps.
- Expand scanner fixtures across more distributions and command variants.
- Add reminder surfaces for upcoming suppression review dates.

## Implementation Evidence

- [SecurityAgent.cs](../VulcansTrace.Linux.Agent/SecurityAgent.cs)
- [QueryParser.cs](../VulcansTrace.Linux.Agent/Query/QueryParser.cs)
- [ScanData.cs](../VulcansTrace.Linux.Agent/Scanners/ScanData.cs)
- [FirewallScanner.cs](../VulcansTrace.Linux.Agent/Scanners/FirewallScanner.cs)
- [PortScanner.cs](../VulcansTrace.Linux.Agent/Scanners/PortScanner.cs)
- [ServiceScanner.cs](../VulcansTrace.Linux.Agent/Scanners/ServiceScanner.cs)
- [NetworkScanner.cs](../VulcansTrace.Linux.Agent/Scanners/NetworkScanner.cs)
- [Security rules](../VulcansTrace.Linux.Agent/Rules/SecurityRules)
- [AgentViewModel.cs](../VulcansTrace.Linux.Avalonia/ViewModels/AgentViewModel.cs)
- [SecurityAgentTests.cs](../VulcansTrace.Linux.Tests/Agent/SecurityAgentTests.cs)
- [ScannerParserFixtureTests.cs](../VulcansTrace.Linux.Tests/Agent/ScannerParserFixtureTests.cs)
