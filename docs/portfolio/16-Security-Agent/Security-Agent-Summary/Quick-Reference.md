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
| `FilesystemAuditCheck` | `Check my filesystem` | Filesystem audit rules (world-writable files, SUID/SGID, unowned files, sticky bit, /tmp hardening) |
| `KernelCheck` | `Check my kernel hardening` | Kernel and system hardening posture rules |
| `UserAccountCheck` | `Check my user accounts` | User account, password aging, and PAM posture rules |
| `LoggingAuditCheck` | `Check my logging` | rsyslog, journald, auditd, logrotate, and central forwarding posture rules |
| `CronJobCheck` | `Check my cron jobs` | Cron job posture rules (suspicious entries, world-writable scripts, root jobs for non-root users) |
| `PackageVulnerabilityCheck` | `Check package vulnerabilities` | Package vulnerability posture rules (pending security updates, unattended-upgrades config, known CVEs) |
| `ContainerCheck` | `Check my containers` | Container posture rules (privileged mode, latest tags, socket exposure/mounts, risky base-image hints, namespace isolation) |
| `KubernetesCheck` | `Check my kubernetes` / `Check my pods` | Kubernetes pod security rules (privileged pods, host namespaces, root containers, security contexts) |
| `ThreatIntelCheck` | `Check threat intel` / `Check malicious IPs` | Threat intel correlation rules (TI-001, TI-002, TI-003) against imported STIX/MISP IOCs |
| `YaraCheck` | `Run a YARA scan` / `Check for malware signatures` | YARA rule scanning (YARA-001) for SUID/SGID binaries, running process executables, and cron scripts against bundled and custom rules |
| `ExplainFinding` | `Explain FW-001` | Resolve previous finding by rule ID, or run one matching rule |
| `ExplainFinding` | `Explain this finding` | Explain the selected UI finding when one is selected |
| `ShowChanges` | `What changed since the last audit?` | Diff against previous history entry; skips the entry matching the current result's timestamp |
| `ExplainCritical` | `Why is this critical?` | Explain Critical/High findings from the last audit |
| `FilterCategory` | `Show only firewall issues` | Filter last audit by category; falls back to fresh category audit if no context |
| `PrioritizeRemediation` | `What should I fix first?` | Severity-ordered remediation plan from the last audit |
| `FixFinding` | `Fix FW-001` | Single-finding remediation preview when rollback guidance is present |
| `StartRemediation` | `Remediate FW-001` | Persisted guided remediation session with before snapshot, step state, and immutable event timeline |
| `VerifyRemediation` | `Verify remediation abc12345` | Re-run the session's audit intent and report fixed, unchanged, new, and worsened findings; blocked or failed verification is recorded in the timeline |
| `ListRemediationSessions` | `List my sessions` / `Show sessions` | List all persisted remediation sessions with ID, status, rule ID, and creation time |
| `ResumeRemediation` | `Resume session abc12345` | Reload a previously saved remediation session into the chat panel for review or continued verification |
| Auto-Fix CLI | `--auto-fix` | Batch auto-remediation; supports `--dry-run` to preview, `--policy` (Conservative/Standard/Aggressive), `--allow-restart`, `--allow-packages`, and `--yes` to skip confirmation. Automatically skips risky commands missing rollback guidance. |
| `ListSuppressed` | `Which findings are suppressed?` | List suppressed findings from the last audit |
| `SetBaseline` | `Set baseline` | Save the last audit as a known-good baseline snapshot |
| `CheckDrift` | `Check drift` | Compare live config against the saved baseline; reports new and worsened findings |
| `ShowBaseline` | `Show baseline` | Display the active baseline findings for the last audit intent |
| `RiskScore` | `What's my risk grade?` | Returns the aggregate Risk Scorecard after an audit |
| `Help` | `What can you do?` | Help text only |

---

## Compliance Scorecard

| Element | Detail |
| --- | --- |
| Overall score | Rule-level pass rate (0–100%), rounded to 1 decimal |
| Family scores | Passed, Failed, Crashed, Suppressed, Total per CIS family |
| Pass threshold | ≥90% (`ComplianceScorecard.PassThreshold`) |
| Warn threshold | ≥80% (`ComplianceScorecard.WarnThreshold`) |
| Fail threshold | <80% or any crashed rule |
| Trend | Last 10 audit history entries, bar-chart visualization |
| NotApplicable handling | Excluded from scoring entirely |
| Suppressed handling | Excluded from applicable denominator |
| Multi-family rules | Counted once per family for family scores; rule-level for overall |
| Export formats | `compliance-scorecard.html`, `compliance-scorecard.md` in signed ZIP |

---

## Risk Scorecard

| Element | Detail |
| --- | --- |
| Overall score | 0–100 (100 = no risk), rounded to 1 decimal |
| Grade | A (≥90), B (≥80), C (≥70), D (≥60), F (<60) |
| Summary status | Low, Moderate, Elevated, High, Severe |
| Category breakdown | Finding count, average severity, total deduction per category; ordered by deduction |
| Scoring formula | `SeverityValue × 5 × AverageControlWeight` per finding |
| Control weight | Average of `CisBenchmarkMapping.ControlWeight` (default 1.0; guards against ≤0, NaN, Infinity, >1000) |
| Info findings | Excluded from score and count |
| Grade computation | From raw score before rounding |
| Export formats | `risk-scorecard.html`, `risk-scorecard.md` in signed ZIP |

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
| `FilesystemAuditScanner` | `find / -xdev … -exec stat …`, `findmnt /tmp` | `FilesystemAudits`, `TmpMountOptions`, `TmpMountTarget` |
| `KernelHardeningScanner` | `/proc/sys/*` reads, `sysctl -a` fallback, `mokutil --sb-state` | `KernelParameters` |
| `UserAccountScanner` | `/etc/passwd`, `/etc/shadow`, `/etc/login.defs`, PAM configs, `/etc/security/pwquality.conf` | `UserAccounts`, `ShadowEntries`, `LoginDefs`, `PamConfig` |
| `LoggingAuditScanner` | `systemctl is-active rsyslog journald auditd`, `auditctl -l`, `/etc/audit/audit.rules`, `/etc/logrotate.conf`, `/etc/rsyslog.conf`, `/etc/rsyslog.d/*.conf`, `/etc/systemd/journald.conf` | `LoggingAudit` |
| `CronJobScanner` | `/etc/crontab`, `/etc/cron.d/*`, `/var/spool/cron/crontabs/*`, `stat` on referenced scripts | `CronJobs` |
| `PackageVulnerabilityScanner` | `dpkg-query -W`, `apt list --upgradeable`, `apt-cache policy`, `debsecan` (optional), `/etc/apt/apt.conf.d/50unattended-upgrades` | `PackageVulnerabilities` |
| `ContainerScanner` | `docker ps`, `docker inspect`, `crictl ps`, `ctr namespace ls` | `Containers`, `ContainerRuntime` |
| `KubernetesScanner` | `kubectl get pods --all-namespaces -o json` | `KubernetesPods` |
| `FileHashScanner` | `find / -xdev …` + `sha256sum` / `md5sum` / `sha1sum` | `FileHashes` (SHA-256, MD5, SHA-1) |
| `YaraScanner` | `find / -xdev …`, `/proc/<pid>/exe` resolution, reads `/etc/cron.d*/*`; uses `libyara` via P/Invoke | `YaraMatches` — bundled rules (`Scanners/Yara/Rules/bundled.yar`) plus optional custom rules in `~/.config/VulcansTrace/yara/*.yar` |

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
| FilesystemAudit | world-writable files, SUID/SGID binaries, unowned files, sticky-bit dirs, /tmp mount hardening | 5/5 rules mapped to CIS 1.1.2 / 6.1.9-12 + Ubuntu 1.1.2.x / 6.1.9-12 |
| Kernel | ASLR, IP forwarding, ICMP redirects, source routing, module loading, Secure Boot, pointer exposure | 7/7 rules mapped to CIS 1.4 / 1.5 / 3.1 + Ubuntu 1.4.x / 1.5.x / 3.1.x |
| UserAccount | UID 0 beyond root, empty passwords, password aging, PAM complexity, inactive accounts, duplicate UIDs, missing home directories | 7/7 rules mapped to CIS 5.4 / 6.2 + Ubuntu 5.4.x / 6.2.x |
| Logging | rsyslog/journald active, auditd active, auditd rules configured, logrotate configured, central forwarding, privilege escalation monitoring, TCP forwarding | 7/7 rules mapped to CIS 8.1 / 8.2 / 8.3 / 8.4 + Ubuntu 4.1.x / 4.2.x / 4.3.x |
| CronJob | suspicious cron entries, world-writable cron scripts, root cron jobs for non-root users | 3/3 rules mapped to CIS 5.1 / 6.1 |
| PackageVulnerability | pending security updates, unattended-upgrades configuration, known CVEs | 2/3 rules mapped to CIS 1.9 + Ubuntu 1.9 |
| Container | privileged containers, latest tags, Docker socket exposure/mounts, risky base-image hints, containerd namespace defaults | 5/5 rules mapped to CIS Docker/Containerd Benchmark |
| Kubernetes | privileged pods, hostNetwork/hostPID/hostIPC, root containers, missing security contexts | 4/4 rules mapped to CIS Kubernetes Benchmark 5.2.x |
| ThreatIntel | active connections to malicious IPs, open ports matching malicious ports, file hashes matching known malicious hashes | 3/3 rules (TI-001, TI-002, TI-003) with MITRE ATT&CK T1071/T1571/T1204.002 mappings |
| Yara | YARA rule matches on SUID/SGID binaries, running process executables, and cron scripts | 1/1 rule (YARA-001) mapped to CIS Controls v8 10.1 |

All rules **except the three threat intel rules** carry dual-layer CIS mappings:
- **CIS Controls v8** (organizational): `CIS 4.1`, `CIS 4.5`, `CIS 4.8`, `CIS 5.2`, `CIS 5.4`, `CIS 6.2`, `CIS 6.3`, `CIS 13.3`
- **CIS Ubuntu 24.04 LTS Benchmark** (technical): specific section references such as `5.2.7 Ensure SSH root login is disabled` and `5.1.8 Ensure cron is restricted to authorized users`

Mappings flow through full audits, single-rule explanations (`explain FW-001`), crash results, policy-disabled results, and all evidence export formats (CSV, HTML, Markdown, JSON, STIX).

---

## Agent Flow

```
User query
  -> QueryParser
  -> AgentQuery (Intent + optional TargetReference)
  -> SecurityAgent
  -> ScannerCoordinator
  -> ScanDataBuilder / ScanData
  -> AgentResultComposer (data-source capability report)
  -> RuleEvaluationService
  -> Rule policy provider + rules / contextual rules
  -> FindingAssemblyService
  -> Finding records + stable fingerprints
  -> AgentLogAnalysisService (optional pasted logs)
  -> AgentResultFinalizer
  -> AgentResult + AgentAuditState
  -> AgentFollowUpService / FindingExplanationService / BaselineDriftService (follow-up paths)
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
| Quick actions | Runs full audit, firewall, ports, services, network, SSH, file permissions, filesystem audit, kernel hardening, user accounts, logging, cron jobs, package vulnerabilities, containers, kubernetes, threat intel, YARA scan, explain selected, export audit, export remediation, compare last two audits, compare selected audits, set baseline, check drift, and show baseline without typing |
| Message list | Displays severity summaries, category-grouped findings, warnings, explanation details, and passed-check counts |
| Data-source report | Shows scanner command visibility such as available, unavailable, permission-limited, or unknown |
| Chat filters | Hide/show finding groups by severity and category without changing the underlying audit result |
| Coverage tab | Groups agent rule results by category and shows passed, active failed, suppressed, crashed, and not-applicable check totals |
| Risk Score tab | Shows aggregate Risk Scorecard with color-coded grade badge (A–F), numeric score, summary status, and per-category breakdown |
| Verification commands | Shows copy buttons, safety badges, and SUDO/CHAIN/PIPE/REDIR/DL-EXEC structural badges only for commands from the `How to verify` explanation section |
| Local policy | Applies built-in role defaults and JSON overrides for enabled state, auto-pass, severity, and contextual parameters |
| Privilege banner | Warns when scanner output suggests limited visibility without elevated permissions |
| Accept Risk | Suppresses selected findings by fingerprint when available, falls back to legacy rule-ID/target entries, supports 7/30/90-day or permanent duration, and warns if persistence is unavailable |
| Suppressions tab | Reviews expiring, recently expired, permanent, and stale permanent suppressions with renew, convert, edit, and remove actions |
| Audit history | Persists the latest 50 lightweight audit snapshots by default, tracks successful exports, and compares either the latest two snapshots or selected before/after snapshots with fingerprint matching and a deterministic narrative summary |
| Baseline & drift | Persists intent-scoped baselines to the user config directory. Set Baseline saves the last audit as known-good. Check Drift re-runs the audit and diffs against the active baseline. Show Baseline displays saved findings with original details, categories, and fingerprints preserved |
| Export Audit | Sends the latest agent audit into the shared evidence export flow, including active suppression notes when present |
| Export Remediation | Writes a guarded markdown remediation preview with preconditions, backup/apply/rollback commands, safety notes, structural command warnings, rollback hints, and verification commands |
| Export Session | Writes a markdown guided remediation session report with session status, step state, blocked reasons, before snapshot, remediation plan, timeline, and verification diff when present. Records `Exported` only after the file write succeeds |
| Interactive Remediation Preview | `fix FW-001` surfaces a chat card with preconditions, backup, apply, rollback, and verification commands — each with safety and structural badges. Plans are validated before display; missing rollback guidance for risky commands blocks the card |
| Guided Remediation Session | `remediate FW-001` creates a persisted session. Active sessions can be verified; blocked sessions show safety reasons without exposing command cards. Verification failure, verification completion, and successful export are terminal timeline events |
| Remediation Session History Browser | **Remediation Sessions** expander lists all persisted sessions with ID, status, rule ID, and creation time. Select a session and click **Resume** to reload it into chat, or **Delete** to remove it. Chat commands `list my sessions`, `show sessions`, and `resume session <id>` provide the same functionality |
| Auto-Fix (CLI) | `--auto-fix` applies safe remediation commands in batch. `--dry-run` previews changes without execution. Policy gates determine which `CommandSafety` levels are permitted. Automatically rolls back on apply failure. Exit codes: 0=success, 1=error, 2=unsafe skipped, 3=apply/rollback failure. |
| Automated Incident Response Playbooks | When a critical attack chain (Beaconing → LateralMovement → PrivilegeEscalation) is detected, a **Deploy Countermeasures** button appears on the chain message. Workflow: dry-run preview → confirmation dialog → live execution. Generates `iptables`/`ip6tables` DROP rules and tagged `auditctl -a ... -S connect -k vulcanstrace_countermeasure_<ip>` telemetry. Validates attacker IPs, deduplicates by IP, and verifies firewall rules with exact-rule checks. Blocked if IP is invalid or safety policy rejects the commands. |

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
- Auto-fix is CLI-only. The desktop UI does not yet expose batch remediation; use `fix <rule-id>` for interactive single-finding remediation in the UI.
- Countermeasures require a detected Beaconing → LateralMovement → PrivilegeEscalation triplet and a valid attacker IP. If any stage is missing or the IP is malformed, no countermeasures are generated.
- Countermeasures are desktop UI-only; there is no CLI equivalent for incident response playbooks.
- Countermeasure commands require `sudo` (iptables and auditctl). The executor checks for `RequiresSudo` but does not elevate automatically.
