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
| `SshCheck` | `How's my SSH hardening?` | SSH hardening rules |
| `FilePermissionCheck` | `Check file permissions` | File permission posture rules |
| `ExplainFinding` | `Explain FW-001` | Resolve previous finding by rule ID, or run one matching rule |
| `ExplainFinding` | `Explain this finding` | Explain the selected UI finding when one is selected |
| `ShowChanges` | `What changed since the last audit?` | Diff against previous history entry; skips the entry matching the current result's timestamp |
| `ExplainCritical` | `Why is this critical?` | Explain Critical/High findings from the last audit |
| `FilterCategory` | `Show only firewall issues` | Filter last audit by category; falls back to fresh category audit if no context |
| `PrioritizeRemediation` | `What should I fix first?` | Severity-ordered remediation plan from the last audit |
| `FixFinding` | `Fix FW-001` | Interactive, step-by-step guided remediation for a specific finding |
| `ListSuppressed` | `Which findings are suppressed?` | List suppressed findings from the last audit |
| `SetBaseline` | `Set baseline` | Save the last audit as a known-good baseline snapshot |
| `CheckDrift` | `Check drift` | Compare live config against the saved baseline; reports new and worsened findings |
| `ShowBaseline` | `Show baseline` | Display the active baseline findings for the last audit intent |
| `Help` | `What can you do?` | Help text only |

---

## Scanner Catalog

| Scanner | Commands | Output model |
| --- | --- | --- |
| `FirewallScanner` | `iptables -L -n -v`, `nft list ruleset` | `FirewallRaw`, `FirewallRules`, `FirewallActive` |
| `PortScanner` | `ss -tulnp`, `netstat -tulnp` | `OpenPorts` |
| `ServiceScanner` | `systemctl list-units --type=service --state=running --no-pager --no-legend` | `RunningServices` |
| `NetworkScanner` | `ip addr`, `ip route`, `ss -tunap` | `NetworkInterfaces`, `Routes`, `ActiveConnections` |
| `SshConfigScanner` | `sshd -T`, fallback `/etc/ssh/sshd_config` + includes | `SshConfig` |
| `FilePermissionScanner` | `stat -c '%a %U %G %n'` | `FilePermissions` |

---

## Rule Catalog

| Category | Rules | CIS Coverage |
| --- | --- | --- |
| Firewall | active firewall, default INPUT policy, SSH exposure, state tracking, ICMP posture | 5/5 rules mapped to CIS 4.5 + Ubuntu 3.5.x |
| Port | SSH default port, all-interface listeners, exposed database ports, unknown high ports | 4/4 rules mapped to CIS 4.1 / 4.8 / 13.3 + Ubuntu 3.5.x |
| Service | telnet, FTP, SSH presence, legacy r-services, unnecessary services | 5/5 rules mapped to CIS 4.1 / 4.8 + Ubuntu 2.2.x |
| Network | default route, suspicious outbound connections, interface state, loopback exposure | 4/4 rules mapped to CIS 4.1 / 13.3 + Ubuntu 3.5.x |
| SSH | root login, password auth, auth retries, protocol version, empty passwords, pubkey auth, X11 forwarding | 7/7 rules mapped to CIS 5.2 / 5.4 / 6.3 / 4.8 + Ubuntu 5.2.x |
| FilePermission | shadow, passwd, SSH host keys, root SSH dir, cron world-writable, crontab, user SSH dirs | 7/7 rules mapped to CIS 5.2 / 6.1 + Ubuntu 5.2.x / 6.1.x |

All 32 rules carry dual-layer CIS mappings:
- **CIS Controls v8** (organizational): `CIS 4.1`, `CIS 4.5`, `CIS 4.8`, `CIS 5.2`, `CIS 5.4`, `CIS 6.3`, `CIS 13.3`
- **CIS Ubuntu 24.04 LTS Benchmark** (technical): specific section references such as `5.2.7 Ensure SSH root login is disabled`

Mappings flow through full audits, single-rule explanations (`explain FW-001`), crash results, policy-disabled results, and all evidence export formats (CSV, HTML, Markdown, JSON, STIX).

---

## Agent Flow

```
User query
  -> QueryParser
  -> AgentQuery (Intent + optional TargetReference)
  -> SecurityAgent
  -> Scanners
  -> ScanDataBuilder / ScanData
  -> Data-source capability report
  -> Rule policy provider
  -> Rules / contextual rules
  -> Finding records
  -> Finding fingerprints
  -> ExplanationProvider
  -> AgentResult
  -> BaselineStore (optional save)
  -> AuditDiffCalculator (drift comparison)
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
| Quick actions | Runs full audit, firewall, ports, services, network, SSH, file permissions, explain selected, export audit, export remediation, compare last two audits, compare selected audits, set baseline, check drift, and show baseline without typing |
| Message list | Displays severity summaries, category-grouped findings, warnings, explanation details, and passed-check counts |
| Data-source report | Shows scanner command visibility such as available, unavailable, permission-limited, or unknown |
| Chat filters | Hide/show finding groups by severity and category without changing the underlying audit result |
| Coverage tab | Groups agent rule results by category and shows passed, active failed, suppressed, and crashed check totals |
| Verification commands | Shows copy buttons, safety badges, and SUDO/CHAIN/PIPE/REDIR/DL-EXEC structural badges only for commands from the `How to verify` explanation section |
| Local policy | Applies built-in role defaults and JSON overrides for enabled state, auto-pass, severity, and contextual parameters |
| Privilege banner | Warns when scanner output suggests limited visibility without elevated permissions |
| Accept Risk | Suppresses selected findings by fingerprint when available, falls back to legacy rule-ID/target entries, supports 7/30/90-day or permanent duration, and warns if persistence is unavailable |
| Suppressions tab | Reviews expiring, recently expired, permanent, and stale permanent suppressions with renew, convert, edit, and remove actions |
| Audit history | Persists the latest 50 lightweight audit snapshots by default, tracks successful exports, and compares either the latest two snapshots or selected before/after snapshots with fingerprint matching and a deterministic narrative summary |
| Baseline & drift | Persists intent-scoped baselines to the user config directory. Set Baseline saves the last audit as known-good. Check Drift re-runs the audit and diffs against the active baseline. Show Baseline displays saved findings with original details, categories, and fingerprints preserved |
| Export Audit | Sends the latest agent audit into the shared evidence export flow, including active suppression notes when present |
| Export Remediation | Writes a guarded markdown remediation preview with preconditions, backup/apply/rollback commands, safety notes, structural command warnings, rollback hints, and verification commands |
| Interactive Remediation | `fix FW-001` surfaces a chat card with preconditions, backup, apply, rollback, and verification commands — each with safety and structural badges. Plans are validated before display; missing rollback guidance for risky commands blocks the card |

---

## Limitations

- Scanner output parsing is command-text based and should continue expanding with distro-specific fixtures.
- Some checks are posture findings, not compromise findings.
- Privilege-sensitive command output may be incomplete without elevated permissions.
- Capability status describes scanner command visibility, not a guarantee that every host fact was collected.
- Direct selected-finding explanations summarize the existing finding details.
- New suppressions match finding fingerprints when available. Legacy entries without fingerprints match exact rule IDs and targets. Expired suppressions are inactive immediately but remain reviewable for 30 days before pruning.
- Command safety labels are keyword-based classifications and should be reviewed before use.
- The desktop UI currently uses the `Workstation` role until a role selector exists.
- The agent is deterministic and rule-based, not a general LLM conversation layer.
