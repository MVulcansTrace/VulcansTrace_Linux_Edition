> **At-a-glance reference** for the Security Agent subsystem: intents, scanners, rules, commands, and known limitations.

---

## Intent Catalog

| Intent | Example query | Behavior |
| --- | --- | --- |
| `FullAudit` | `Is my system secure?` | All rules |
| `FirewallCheck` | `Check my firewall` | Firewall rules |
| `NetworkCheck` | `Who am I talking to?` | Network rules |
| `ServiceCheck` | `What services are running?` | Service rules |
| `PortCheck` | `What ports are open?` | Port rules |
| `ExplainFinding` | `Explain FW-001` | Resolve previous finding by rule ID, or run one matching rule |
| `ExplainFinding` | `Explain this finding` | Explain the selected UI finding when one is selected |
| `Help` | `What can you do?` | Help text only |

---

## Scanner Catalog

| Scanner | Commands | Output model |
| --- | --- | --- |
| `FirewallScanner` | `iptables -L -n -v`, `nft list ruleset` | `FirewallRaw`, `FirewallRules`, `FirewallActive` |
| `PortScanner` | `ss -tulnp`, `netstat -tulnp` | `OpenPorts` |
| `ServiceScanner` | `systemctl list-units --type=service --state=running --no-pager --no-legend` | `RunningServices` |
| `NetworkScanner` | `ip addr`, `ip route`, `ss -tunap` | `NetworkInterfaces`, `Routes`, `ActiveConnections` |

---

## Rule Catalog

| Category | Rules |
| --- | --- |
| Firewall | active firewall, default INPUT policy, SSH exposure, state tracking, ICMP posture |
| Port | SSH default port, all-interface listeners, exposed database ports, unknown high ports |
| Service | telnet, FTP, SSH presence, legacy r-services, unnecessary services |
| Network | default route, suspicious outbound connections, interface state, loopback exposure |

---

## Agent Flow

```
User query
  -> QueryParser
  -> AgentQuery (Intent + optional TargetReference)
  -> SecurityAgent
  -> Scanners
  -> ScanDataBuilder / ScanData
  -> Rules
  -> Finding records
  -> ExplanationProvider
  -> AgentResult
  -> UI and/or AgentReportGenerator
```

---

## UI Behavior

| UI piece | Behavior |
| --- | --- |
| Security Agent expander | Collapsible chat panel in the main window |
| Query textbox | Accepts plain-English questions |
| Send command | Runs `IAgent.AskAsync` with cancellation support |
| Cancel command | Cancels the current agent operation |
| Main log binding | Shares `MainViewModel.LogText` with `AgentViewModel.LogText` |
| Findings selection | Tracks selected finding and uses it for `explain this finding` |
| Message list | Displays summaries, warnings, findings, and explanation details |

---

## Limitations

- Scanner output parsing is command-text based and should be expanded with distro-specific fixtures.
- Some checks are posture findings, not compromise findings.
- Privilege-sensitive command output may be incomplete without elevated permissions.
- Direct selected-finding explanations summarize the existing finding details.
- The agent is deterministic and rule-based, not a general LLM conversation layer.
