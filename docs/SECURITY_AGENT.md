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
| `Explain this finding` | `ExplainFinding` | Runs the explanation-oriented audit path |
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

1. `QueryParser` converts the user query into an `AgentIntent`.
2. `SecurityAgent` runs the required scanners with cancellation support.
3. `ScanDataBuilder` collects scanner output into a thread-safe snapshot.
4. Rules matching the requested intent evaluate the snapshot.
5. Failed rules become `Finding` records.
6. `ExplanationProvider` fills markdown templates for each finding.
7. If raw log text is available, `SentryAnalyzer` can add log-derived findings.
8. `AgentReportGenerator` can merge agent findings and log findings into an `AnalysisResult`.

## UI Integration

The Avalonia application exposes the agent in a collapsible Security Agent panel. The panel supports:

- Chat-style natural-language questions.
- In-flight query cancellation.
- Agent findings displayed with severity and explanatory details.
- Automatic sharing of the main log input with the agent so pasted firewall logs can be included in agent analysis.

## Privacy And Safety

- The agent is local-only.
- It does not make network calls for analysis.
- It reads host state through local Linux commands.
- It does not modify firewall rules, services, network interfaces, routes, or files.
- It reports warnings when data cannot be collected.

## Current Limitations

- It is a deterministic rule-based assistant, not an LLM-backed conversational system.
- `ExplainFinding` currently runs the explanation-oriented all-rules path; it does not yet target a selected UI finding.
- Scanner parsers are pragmatic and command-output based, so unusual distro output may need parser tests and adjustments.
- Some findings are posture checks rather than proof of compromise.
- Process names and firewall details may require elevated privileges depending on the host.

## Roadmap

- Add a true selected-finding explanation flow.
- Add parser unit tests for representative `ss`, `ip addr`, `iptables`, `nft`, and `systemctl` output.
- Add explicit UI buttons for common commands such as full audit, firewall check, and ports check.
- Group agent findings by severity and category in the UI.
- Add optional remediation guidance with clear "review before applying" language.

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
