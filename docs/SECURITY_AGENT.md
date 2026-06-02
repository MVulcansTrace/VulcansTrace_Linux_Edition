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
| `Check my SSH` | `SshCheck` | Reviews SSH daemon hardening configuration |
| `Check file permissions` | `FilePermissionCheck` | Reviews sensitive file and directory permissions |
| `Check my filesystem` | `FilesystemAuditCheck` | Reviews world-writable files, SUID/SGID binaries, unowned files, sticky-bit checks, and /tmp mount hardening |
| `Check my kernel hardening` | `KernelCheck` | Reviews kernel and system hardening parameters |
| `Check my user accounts` | `UserAccountCheck` | Reviews user accounts, password aging, PAM complexity, and shadow entries |
| `Check my logging` | `LoggingAuditCheck` | Reviews rsyslog, journald, auditd, logrotate, and central forwarding configuration |
| `Check my cron jobs` | `CronJobCheck` | Reviews cron entries for suspicious commands, world-writable scripts, and root jobs referencing user paths |
| `Check package vulnerabilities` | `PackageVulnerabilityCheck` | Reviews installed packages for pending security updates and known CVEs |
| `Explain FW-001` | `ExplainFinding` | Explains a cached finding by rule ID, or runs that single rule if needed |
| `Explain this finding` | `ExplainFinding` | Explains the currently selected UI finding when one is selected |
| `What changed since the last audit?` | `ShowChanges` | Diff the current audit against the previous history entry |
| `Why is this critical?` | `ExplainCritical` | Explain only Critical/High findings from the last audit |
| `Show only firewall issues` | `FilterCategory` | Filter the last audit's findings by category (falls back to a fresh category audit when no context exists) |
| `What should I fix first?` | `PrioritizeRemediation` | Build a severity-ordered remediation plan from the last audit |
| `Fix FW-001` | `FixFinding` | Interactive, step-by-step guided remediation for a specific finding |
| `Which findings are suppressed?` | `ListSuppressed` | List suppressed findings from the last audit |
| `Set baseline` | `SetBaseline` | Save the last audit as a known-good baseline snapshot |
| `Check drift` | `CheckDrift` | Compare live config against the saved baseline and report new/worsened findings |
| `Show baseline` | `ShowBaseline` | Display the active baseline findings for the last audit intent |
| `What's my risk grade?` | `RiskScore` | Returns the aggregate risk scorecard after an audit |
| `Help` | `Help` | Returns supported agent capabilities |

## Data Sources

The agent reads local host state using common Linux tools:

| Scanner | Commands | Purpose |
| --- | --- | --- |
| `FirewallScanner` | `iptables -L -n -v`, fallback `nft list ruleset` | Reads firewall posture and rule text |
| `PortScanner` | `ss -tulnp`, fallback `netstat -tulnp` | Finds listening TCP/UDP ports and owning processes when visible |
| `ServiceScanner` | `systemctl list-units --type=service --state=running --no-pager --no-legend` | Finds running systemd services |
| `NetworkScanner` | `ip addr`, `ip route`, `ss -tunap` | Reads interfaces, routes, and active connections |
| `SshConfigScanner` | `sshd -T`, fallback `/etc/ssh/sshd_config` + includes | Reads SSH daemon hardening directives |
| `FilePermissionScanner` | `stat -c '%a %U %G %n'` | Reads permission bits, ownership, and existence of sensitive files and directories |
| `FilesystemAuditScanner` | `find / -xdev … -exec stat …` | Discovers world-writable files, SUID/SGID binaries, unowned files, world-writable dirs without sticky bit, and /tmp mount options |
| `KernelHardeningScanner` | `/proc/sys/*` direct reads, fallback `sysctl -a`, `mokutil --sb-state` | Reads kernel parameters (ASLR, IP forwarding, ICMP redirects, source routing, module loading, pointer exposure) and Secure Boot status |
| `UserAccountScanner` | `/etc/passwd`, `/etc/shadow`, `/etc/login.defs`, PAM password-stack configs (`common-password`, `system-auth`, `password-auth`), PAM auth-stack configs (`common-auth`, `/etc/pam.d/sshd`), `/etc/security/pwquality.conf`, `/etc/security/faillock.conf` | Reads local user accounts, shadow entries, password aging policy, PAM password-stack and auth-stack configuration, and faillock settings |
| `LoggingAuditScanner` | `systemctl is-active rsyslog journald auditd`, `auditctl -l`, `/etc/audit/audit.rules`, `/etc/logrotate.conf`, `/etc/rsyslog.conf`, `/etc/rsyslog.d/*.conf`, `/etc/systemd/journald.conf` | Checks logging service status, auditd rules, logrotate configuration, and central forwarding targets |
| `CronJobScanner` | Reads `/etc/crontab`, `/etc/cron.d/*`, `/var/spool/cron/crontabs/*`, `/var/spool/cron/*`, `/etc/cron.daily/*`, `/etc/cron.hourly/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`; uses `stat` for script permissions | Parses system and user crontabs and cron script directories for scheduled job entries and script permissions |
| `PackageVulnerabilityScanner` | `dpkg-query -W`, `apt list --upgradeable`, `apt-cache policy`, optionally `debsecan --format report --only-fixed`, `/etc/apt/apt.conf.d/50unattended-upgrades`, `/etc/apt/apt.conf.d/20auto-upgrades` | Enumerates installed packages, detects pending security updates from security repositories, enriches with CVE IDs when debsecan is available, and checks unattended-upgrades configuration |

Scanner failures are reported as warnings instead of crashing the agent. Scanner commands use a shared bounded runner with concurrent stdout/stderr capture, a 30-second default timeout, cancellation propagation, and 1 MiB stdout/stderr limits. `FilesystemAuditScanner` uses the same runner with a 60-second timeout for broader `find` scans. Some commands may expose less detail without elevated privileges, especially process names, firewall rules, `sshd -T` host key access, and `stat` on files owned by other users.

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

### SSH

- Direct root login should be disabled or limited to key-based auth (`PermitRootLogin`).
- Password authentication should be disabled in favor of key-based auth (`PasswordAuthentication`).
- Maximum authentication attempts per connection should be low (`MaxAuthTries`).
- Legacy SSH Protocol 1 should not be enabled (`Protocol`).
- Empty passwords should not be permitted (`PermitEmptyPasswords`).
- Public-key authentication should be enabled (`PubkeyAuthentication`).
- X11 forwarding should be disabled on servers (`X11Forwarding`).
- UsePAM should be enabled to enforce local PAM policies (`UsePAM`) (`SSH-008`).

### Kernel

- ASLR should be fully enabled (`kernel.randomize_va_space >= 2`) (`KERN-001`).
- IP forwarding should be disabled on non-router hosts (`net.ipv4.ip_forward`, `net.ipv6.conf.all.forwarding`) (`KERN-002`).
- ICMP redirects should be disabled (`net.ipv4.conf.all.accept_redirects`, `net.ipv6.conf.all.accept_redirects`) (`KERN-003`).
- Source routed packets should be rejected (`net.ipv4.conf.all.accept_source_route`) (`KERN-004`).
- Kernel module loading should be restricted (`kernel.modules_disabled != 0`); severity is High on Server, Medium on Workstation (`KERN-005`).
- Secure Boot should be enabled on UEFI systems; BIOS systems return NotApplicable (`KERN-006`).
- Kernel pointer and dmesg exposure should be restricted (`kernel.kptr_restrict >= 1`, `kernel.dmesg_restrict == 1`) (`KERN-007`).

### File Permissions

- `/etc/shadow` should be `640` or `600` and owned by root (`FILE-001`).
- `/etc/passwd` should be `644` and owned by root (`FILE-002`).
- SSH host private keys should be `600` and owned by root (`FILE-003`).
- `/root/.ssh` should be `700` and `/root/.ssh/authorized_keys` should be `600` (`FILE-004`).
- Cron directories should not be world-writable (`FILE-005`).
- `/etc/crontab` should be `644` or `600` and owned by root (`FILE-006`).
- User SSH directories (`/home/*/.ssh`) should be `700` and user `authorized_keys` files should be `600` (`FILE-007`).

### Filesystem Audit

- World-writable files outside expected temporary paths (`/tmp`, `/var/tmp`, `/dev/shm`, `/var/cache`, `/var/spool`) are flagged (`FSYS-001`).
- SUID/SGID binaries that do not match the known-good full-path whitelist are flagged (`FSYS-002`).
- Files with no valid owner or group are flagged (`FSYS-003`).
- World-writable directories without the sticky bit are flagged (`FSYS-004`).
- `/tmp` should be a separate mount with `noexec`, `nosuid`, and `nodev` options (`FSYS-005`).

### User Accounts

- Only `root` should have UID 0; additional UID-0 accounts are flagged (`USER-001`).
- Empty or unset password hashes are flagged; locked interactive accounts are flagged at lower severity (`USER-002`).
- Password aging should enforce rotation via `PASS_MAX_DAYS <= 90`, `PASS_MIN_DAYS >= 1`, and `PASS_WARN_AGE >= 7` in `/etc/login.defs`, plus per-user shadow `max_days` checks (`USER-003`).
- PAM password-stack should include a complexity module (`pam_pwquality.so`, `pam_cracklib.so`, or `pam_passwdqc.so`) (`USER-004`).
- Inactive or locked interactive accounts (UID >= 1000) with expired account expiry dates are flagged (`USER-005`).
- Each UID should be unique (`USER-006`).
- Regular interactive accounts (UID >= 1000) should have an existing home directory (`USER-007`).
- PAM faillock must be configured in every auth stack (`preauth` + `authfail`) with a readable `faillock.conf` (`USER-008`).
- PAM password quality must enforce `minlen >= 14`, `minclass >= 3`, and credit requirements (`dcredit`, `ucredit`, `lcredit`, `ocredit`) (`USER-009`).
- PAM auth stack must place `required`/`requisite`/`binding` or bracketed controls before any `sufficient` module in every file (`USER-010`).

### Logging

- At least one system logging service (rsyslog or journald) should be active (`LOG-001`).
- auditd should be installed and active (`LOG-002`).
- auditd should have active rules monitoring key security events (`LOG-003`). Returns `NotApplicable` when auditd rules could not be read (permission denied).
- Log rotation should be configured via logrotate (`LOG-004`).
- Central log forwarding should be configured (rsyslog remote or journald `ForwardToSyslog`); exempt on Workstation, DevMachine, LabBox, and Router (`LOG-005`).
- auditd should monitor privilege escalation syscalls (`setuid`, `setgid`, etc.) (`LOG-006`). Returns `NotApplicable` when auditd rules could not be read.
- Central forwarding should use TCP (`@@` target) rather than UDP (`@`) for reliability (`LOG-007`).

### Cron Jobs

- Cron entries should not contain suspicious commands such as reverse shells, network downloaders (`wget`, `curl`, `nc`), temporary paths (`/tmp/`, `/var/tmp/`, `/dev/shm/`), or encoded payloads (`python -c`, `perl -e`, etc.). Pattern matching uses word-boundary awareness to reduce false positives (`CRON-001`).
- Script files in `cron.daily`, `cron.hourly`, `cron.weekly`, and `cron.monthly` should not be world-writable. Setuid/setgid bits on cron scripts are escalated to `Critical` severity (`CRON-002`).
- System crontab entries running as `root` should not reference non-root user directories (e.g., paths under `/home/` or `~username` expansions) (`CRON-003`).
- All cron rules return `NotApplicable` when no cron data is available (requires root or cron files not present).

### Package Vulnerability

- Pending security updates from security repositories should be applied promptly. Severity escalates to `Critical` when 5 or more security updates are pending (`PKG-VULN-001`).
- Automatic security updates via `unattended-upgrades` should be configured (`PKG-VULN-002`).
- Known CVEs affecting installed packages should be tracked and patched. Returns `NotApplicable` when CVE enrichment data (debsecan) is unavailable, preventing false confidence on systems without CVE data (`PKG-VULN-003`).
- All package vulnerability rules return `NotApplicable` when package data is unreadable (dpkg-query failed or permission denied).

## How The Pipeline Works

1. `QueryParser` converts the user query into an `AgentQuery` containing an `AgentIntent`, confidence, optional alternative intents, and optional target reference. Ambiguous audit-area prompts ask for clarification instead of running a guessed check.
2. `SecurityAgent` acts as the orchestration entry point and delegates scanner execution to `ScannerCoordinator`.
3. `ScanDataBuilder` collects scanner output and data-source capability status into a thread-safe snapshot.
4. `RuleEvaluationService` resolves built-in role defaults and user overrides from `~/.config/VulcansTrace/policy.json`, filters rules by intent, invokes contextual rules when they opt into `IContextualRule`, converts crashes into explicit rule results, and applies disabled, auto-pass, and severity override policy.
5. `FindingAssemblyService` converts failed rule results into `Finding` records with stable fingerprints derived from rule ID, category, source host, and target. Severity, timestamps, and description text are excluded so the same underlying issue can be tracked when its wording or severity changes.
6. `ExplanationProvider` fills markdown templates for each finding and parses them into structured explanation sections.
7. Suppressions expired longer than the 30-day review retention window are pruned, active fingerprint-scoped suppressions are applied first, legacy rule-ID/target suppressions remain supported, and rule pass/fail/suppressed counts are added to `AgentResult`.
8. `AgentResultComposer` builds user-facing audit summaries and deterministic data-source capability reports.
9. `AgentLogAnalysisService` optionally analyzes pasted firewall logs through `SentryAnalyzer` and adds log-derived findings when raw log text is available.
10. `AgentResultFinalizer` attaches `ComplianceScorecardBuilder` and `RiskScorecardBuilder` output, builds the final `AgentResult`, and updates `AgentAuditState` so follow-up questions like `explain FW-001` can resolve without relying on text matching.
11. `AgentFollowUpService`, `FindingExplanationService`, and `SingleRuleExplanationService` answer deterministic follow-up questions and explanation requests without making `SecurityAgent` own those workflows directly.
12. `BaselineDriftService` saves baseline snapshots from audit results and compares live state against the active intent-scoped baseline through `AuditDiffCalculator`. Each baseline stores lightweight `AuditSnapshotFinding` records for diff calculations and preserves the original `Finding` objects for lossless display.
13. `ComplianceScorecardBuilder` produces a formal CIS Compliance Scorecard from rule results: per-family pass/fail/warn scores, overall percentage, and trend over time. The scorecard is surfaced in the Avalonia UI Compliance tab and exported as `compliance-scorecard.html` and `compliance-scorecard.md` in evidence bundles.
14. `RiskScorecardBuilder` produces an aggregate Risk Scorecard from agent findings: numeric score (0-100), letter grade (A-F), summary status, and per-category breakdown ordered by total deduction. It weights each finding by the average `ControlWeight` of its CIS mappings (default 1.0, with guards against zero, negative, NaN, Infinity, and excessive weights). The scorecard is surfaced in the Avalonia UI Risk Score tab, available via agent chat (`what's my risk grade?`), and exported as `risk-scorecard.html` and `risk-scorecard.md` in evidence bundles.
15. `AgentReportGenerator` can merge agent findings and log findings into an `AnalysisResult`; exported CSV, JSON, Markdown, HTML, and STIX evidence preserves agent rule IDs, fingerprints, data-source capability reports, active suppression notes, and risk scorecard data when present.

## Rule Tuning

The agent supports local role-aware policy for `Workstation`, `Server`, `LabBox`, `Router`, and `DevMachine` profiles. Built-in defaults tune selected rules, and user JSON policies take precedence while inheriting built-in parameters that are not overridden.

The policy file lives at `~/.config/VulcansTrace/policy.json`. It can disable a rule, auto-pass a rule, override severity, or provide rule-specific parameters. Current contextual rules include `PORT-001`, `PORT-002`, `SRV-005`, `SSH-007`, `KERN-005`, and `LOG-005`.

The Avalonia composition currently runs the agent as `Workstation`; other roles are available through the agent API and policy provider wiring until a role selector is added.

## Explanation Behavior

The agent supports three explanation paths:

- **Selected finding:** if the user selects a finding in the UI and asks `explain this finding`, `AgentViewModel` calls `ExplainFindingAsync` directly without re-scanning.
- **Previous agent finding:** after an audit, references such as `explain FW-001`, `explain firewall`, or `explain SSH` are resolved against cached agent findings.
- **Known rule ID with no cached finding:** if a rule ID is recognized but no previous finding is available, the agent runs that single rule and explains the result if it fails.

When no selected finding or target reference is available, the agent returns guidance instead of running an unrelated full audit.

Explanations are rendered as structured sections: what was found, why it matters, how to verify, preconditions, backup commands, suggested next action, rollback commands, confidence, and caveats. The UI extracts copyable commands only from the verification section and labels them with a heuristic safety classification plus structural badges for sudo usage, command chains, pipes, redirects, and download-and-execute patterns. Suggested action commands are kept in the explanation/remediation preview path, safety-labeled in exported remediation plans with the same structural warnings, and never applied automatically.

**Interactive Remediation** — When a user asks `fix FW-001` after an audit, the agent builds a single-section `RemediationPlan` for that finding, runs `RemediationPlanValidator` to ensure risky or unclassified commands have explicit rollback guidance, and returns the plan as an interactive remediation card. The card surfaces preconditions as a checklist, backup commands, apply commands, rollback commands, and verification commands — each with the same safety and structural badges used for verification commands. If validation fails because rollback guidance is missing, the plan is blocked and the user is told why.

## UI Integration

The Avalonia application exposes the agent in a collapsible Security Agent panel. The panel supports:

- Chat-style natural-language questions.
- Quick-action buttons for full audit, firewall, ports, services, network, SSH, file permissions, filesystem audit, kernel hardening, user accounts, logging, cron jobs, selected-finding explanation, and audit export.
- Baseline quick-action buttons for **Set Baseline**, **Check Drift**, and **Show Baseline**.
- In-flight query cancellation.
- Data-source capability messages showing whether scanner inputs such as iptables, nftables, ss, netstat, ip, and systemctl were available, unavailable, permission-limited, or not checked.
- Agent findings grouped by category with compact severity summaries.
- Chat filters for severity and category that hide/show finding groups without changing the underlying audit result.
- A Coverage tab after agent audits with totals and category breakdowns for passed, active failed, suppressed, and crashed rule checks.
- A Compliance tab showing the CIS Compliance Scorecard with an overall score badge (Pass ≥90%, Warn ≥80%, Fail <80%), per-family DataGrid with score and status, and a mini bar-chart trend visualization of previous audits.
- A Risk Score tab showing the aggregate Risk Scorecard with a color-coded grade badge (A–F), numeric score, summary status, and a per-category breakdown ordered by total deduction.
- Two-way selection tracking from the findings grid for selected-finding explanations; the Explain Selected action is only enabled when a finding is selected.
- Agent audit results are loaded into the shared findings grid so they can be selected, explained, exported, or suppressed. This includes quick-action audits and typed audit intents such as SSH, file permission, kernel hardening, and cron job checks.
- An elevated-privilege warning banner when scanner output indicates permission-limited visibility.
- Role-aware rule tuning through local policy, currently wired as `Workstation` in the desktop UI.
- Audit history persisted to the user config directory when available, capped at 50 lightweight snapshots by default, with compare-last-two, selectable before/after comparison, deterministic narrative diff summaries, and exported-state tracking after successful evidence export. If persistence fails, the UI reports that history is session-only.
- Configuration baselines persisted to the user config directory (`~/.config/VulcansTrace/baselines.json`) when available, with in-memory fallback. Baselines are intent-scoped; each intent has one active baseline at a time. Drift detection re-runs the last completed audit intent and compares against the active baseline, surfacing new and worsened findings.
- Accept Risk suppressions by finding fingerprint when available, with legacy rule-ID/target matching for older entries. Suppressions can last 7 days, 30 days, 90 days, or permanently. Expired suppressions stop applying immediately, remain in the review queue for 30 days, and are pruned after that retention window. Suppressions are persisted to the user config directory when available; if persistence fails, the UI reports that suppressions are session-only.
- A Suppressions tab with friendly filter labels, review counts, status badges, and row actions to renew, convert duration, edit reason, or remove suppressions.
- Export Audit support that reuses the shared evidence export flow for the latest agent audit and includes active suppression notes when present.
- Export Remediation support that writes a review-only markdown plan with preconditions, backup/apply/rollback command sections, safety notes, rollback hints, and verification commands. Plans with risky or unclassified apply/backup commands are blocked from standalone export and omitted from evidence bundles unless the template includes explicit rollback guidance.
- **Interactive Remediation** (`fix FW-001`) surfaces a single-section remediation card in the chat with preconditions, backup commands, apply commands, rollback commands, and verification commands — each labeled with safety and structural badges. The plan is validated before display; missing rollback guidance for risky commands blocks the card and surfaces the error in chat.
- **Batch Auto-Fix** (`--auto-fix` on the CLI) extends interactive remediation to headless batch mode. After an audit, the CLI can build a `RemediationPlan` for all findings, filter commands through a configurable `AutoFixPolicy`, execute backup/apply/verify phases sequentially, and automatically roll back a section if any apply command fails. `--dry-run` previews the plan without executing anything. The default policy permits `ReadOnly` verification and `ConfigChange` commands; `--allow-restart` and `--allow-packages` expand the policy; destructive and unclassified commands are never auto-executed.
- Automatic sharing of the main log input with the agent so pasted firewall logs can be included in agent analysis.

## Privacy And Safety

- The agent is local-only.
- It does not make network calls for analysis.
- It reads host state through local Linux commands.
- It does not modify firewall rules, services, network interfaces, routes, or files.
- It reports warnings when data cannot be collected.
- It reports data-source capability status so exported evidence shows which local commands informed the audit.

## CIS Benchmark Mapping

Every agent rule maps to **two compliance layers**:

1. **CIS Controls v8** (organizational) — e.g., `CIS 4.5`, `CIS 5.4`, `CIS 6.3`
2. **CIS Ubuntu 24.04 LTS Benchmark** (technical) — e.g., `5.2.7 Ensure SSH root login is disabled`

This dual-layer mapping gives auditors both the high-level organizational control and the exact Linux benchmark section the rule validates. The mapping flows through every execution path: full audits, single-rule explanations, crashes, policy-disabled results, and all evidence exports.

| Rule | CIS Control | Ubuntu Benchmark |
|------|-------------|------------------|
| KERN-001 | CIS 1.5 — Establish and Maintain a Secure Configuration Process | 1.5.2 — Ensure address space layout randomization is enabled |
| KERN-002 | CIS 3.1 — Network Parameters (Host Only) | 3.1.1 — Ensure IP forwarding is disabled |
| KERN-003 | CIS 3.1 — Network Parameters (Host Only) | 3.1.2 — Ensure ICMP redirects are not accepted |
| KERN-004 | CIS 3.1 — Network Parameters (Host Only) | 3.1.3 — Ensure source routed packets are not accepted |
| KERN-005 | CIS 1.4 — Secure Boot Settings | 1.4.1 — Ensure loading and unloading of kernel modules is restricted |
| KERN-006 | CIS 1.4 — Secure Boot Settings | 1.4.2 — Ensure Secure Boot is enabled |
| KERN-007 | CIS 1.5 — Establish and Maintain a Secure Configuration Process | 1.5.3 — Ensure kernel pointer restriction is enabled |
| SSH-001 | CIS 5.4 — Restrict Administrator Privileges | 5.2.7 — Ensure SSH root login is disabled |
| SSH-002 | CIS 6.3 — Require MFA for Externally-Exposed Applications | 5.2.16 — Ensure SSH PasswordAuthentication is disabled |
| SSH-003 | CIS 6.3 — Require MFA for Externally-Exposed Applications | 5.2.14 — Ensure SSH MaxAuthTries is configured |
| SSH-004 | CIS 4.8 — Uninstall or Disable Unnecessary Services | 5.2.15 — Ensure SSH Protocol is set to 2 |
| SSH-005 | CIS 5.2 — Use Unique Passwords | 5.2.9 — Ensure SSH PermitEmptyPasswords is disabled |
| SSH-006 | CIS 6.3 — Require MFA for Externally-Exposed Applications | 5.2.17 — Ensure SSH PubkeyAuthentication is enabled |
| SSH-007 | CIS 4.8 — Uninstall or Disable Unnecessary Services | 5.2.12 — Ensure SSH X11 forwarding is disabled |
| SSH-008 | CIS 5.2 — Use Unique Passwords | 5.2.20 — Ensure SSH PAM is enabled |
| FILE-001 | CIS 6.1 — Configure System File Permissions | 6.1.1 — Ensure permissions on /etc/shadow are configured |
| FILE-002 | CIS 6.1 — Configure System File Permissions | 6.1.2 — Ensure permissions on /etc/passwd are configured |
| FILE-003 | CIS 5.2 — Use Unique Passwords | 5.2.2 — Ensure permissions on SSH private host key files are configured |
| FILE-004 | CIS 5.2 — Use Unique Passwords | 5.2.4 — Ensure permissions on SSH public host key files are configured |
| FILE-005 | CIS 6.1 — Configure System File Permissions | 6.1.3 — Ensure permissions on /etc/cron.* are configured |
| FILE-006 | CIS 6.1 — Configure System File Permissions | 6.1.4 — Ensure permissions on /etc/crontab are configured |
| FILE-007 | CIS 5.2 — Use Unique Passwords | 5.2.4 — Ensure permissions on SSH public host key files are configured |
| FSYS-001 | CIS 6.1.9 — Ensure no world writable files exist | 6.1.9 — Ensure no world writable files exist |
| FSYS-002 | CIS 6.1.12 — Ensure SUID and SGID files are reviewed | 6.1.12 — Ensure SUID and SGID files are reviewed |
| FSYS-003 | CIS 6.1.11 — Ensure no unowned files or directories exist | 6.1.11 — Ensure no unowned files or directories exist |
| FSYS-004 | CIS 6.1.10 — Ensure sticky bit is set on all world-writable directories | 6.1.10 — Ensure sticky bit is set on all world-writable directories |
| FSYS-005 | CIS 1.1.2 — Configure /tmp | 1.1.2.2-4 — Ensure nodev, nosuid, noexec options set on /tmp partition |
| USER-001 | CIS 6.2 — Configure System Account Security | 6.2.1 — Ensure accounts in /etc/passwd use assigned UIDs |
| USER-002 | CIS 5.4 — Configure Password Policies | 5.4.1 — Ensure password creation requirements are configured |
| USER-003 | CIS 5.4 — Configure Password Policies | 5.4.1 — Ensure password creation requirements are configured |
| USER-004 | CIS 5.4 — Configure Password Policies | 5.4.1 — Ensure password creation requirements are configured |
| USER-005 | CIS 6.2 — Configure System Account Security | 6.2.5 — Ensure inactive accounts are locked or removed |
| USER-006 | CIS 6.2 — Configure System Account Security | 6.2.1 — Ensure accounts in /etc/passwd use assigned UIDs |
| USER-007 | CIS 6.2 — Configure System Account Security | 6.2.6 — Ensure all users' home directories exist |
| USER-008 | CIS 5.3 — Configure PAM | 5.3.2 — Ensure lockout for failed password attempts is configured |
| USER-009 | CIS 5.4 — Configure Password Policies | 5.4.1 — Ensure password creation requirements are configured |
| USER-010 | CIS 5.3 — Configure PAM | 5.3.1 — Ensure password hashing algorithm is configured |
| FW-001 | CIS 4.5 — Implement and Manage a Firewall on Servers | 3.5.1.3 / 3.5.2.3 — Ensure default deny firewall policy |
| FW-002 | CIS 4.5 — Implement and Manage a Firewall on Servers | 3.5.1.6 / 3.5.2.6 — Ensure firewall rules exist for all open ports |
| FW-003 | CIS 4.5 — Implement and Manage a Firewall on Servers | 3.5.1.2 / 3.5.2.2 — Ensure iptables/nftables service is enabled |
| FW-004 | CIS 4.5 — Implement and Manage a Firewall on Servers | 3.5.1.1 / 3.5.2.1 — Ensure iptables/nftables is installed |
| FW-005 | CIS 4.5 — Implement and Manage a Firewall on Servers | 3.5.1.5 / 3.5.2.5 — Ensure outbound and established connections are configured |
| PORT-002 | CIS 4.1 — Establish and Maintain a Secure Configuration Process | 3.5.1.6 / 3.5.2.6 — Ensure firewall rules exist for all open ports |
| PORT-003 | CIS 4.1 — Establish and Maintain a Secure Configuration Process | 3.5.1.6 / 3.5.2.6 — Ensure firewall rules exist for all open ports |
| SRV-001 | CIS 4.8 — Uninstall or Disable Unnecessary Services | 2.2.17 — Ensure telnet server is not installed |
| SRV-002 | CIS 4.8 — Uninstall or Disable Unnecessary Services | 2.2.12 — Ensure FTP server is not installed |
| SRV-004 | CIS 4.8 — Uninstall or Disable Unnecessary Services | 2.2.16 — Ensure rsh server is not installed |
| SRV-005 | CIS 4.8 — Uninstall or Disable Unnecessary Services | 2.2.x — Ensure unnecessary services are removed or disabled |
| LOG-001 | CIS 8.1 — Collect and Retain Audit Logs | 4.2.1 — Ensure rsyslog or journald is installed and active |
| LOG-002 | CIS 8.2 — Collect Audit Logs | 4.1.1 — Ensure auditd is installed and active |
| LOG-003 | CIS 8.2 — Collect Audit Logs | 4.1.x — Ensure audit rules are configured |
| LOG-004 | CIS 8.3 — Collect Service Provider Logs | 4.3.x — Ensure logrotate is configured |
| LOG-005 | CIS 8.4 — Collect Audit Log Details | 4.2.2.x — Ensure rsyslog is configured to send logs to a remote log host |
| LOG-006 | CIS 8.2 — Collect Audit Logs | 4.1.x — Ensure audit rules monitor privilege escalation |
| LOG-007 | CIS 8.4 — Collect Audit Log Details | 4.2.2.x — Ensure reliable log forwarding transport |
| CRON-001 | CIS 6.1 — Configure System File Permissions | 6.1.3 — Ensure permissions on /etc/cron.* are configured |
| CRON-002 | CIS 6.1 — Configure System File Permissions | 6.1.3 — Ensure permissions on /etc/cron.* are configured |
| CRON-003 | CIS 6.2 — Configure System Account Security | 6.2.1 — Ensure accounts in /etc/passwd use assigned UIDs |
| PKG-VULN-001 | CIS 1.9 — Ensure updates, patches, and additional security software are installed | 1.9 — Ensure updates, patches, and additional security software are installed |
| PKG-VULN-002 | CIS 1.9 — Ensure updates, patches, and additional security software are installed | 1.9 — Ensure updates, patches, and additional security software are installed |

The remaining rules (NET-001 through NET-004, PORT-001, PORT-004, SRV-003, PKG-VULN-003) map to CIS Controls v8 where no direct Ubuntu benchmark section exists. KERN-006 returns `NotApplicable` on BIOS systems where Secure Boot is unavailable. PKG-VULN-003 returns `NotApplicable` when CVE enrichment data (debsecan) is unavailable.

Mappings are defined on `IRule.CisMappings`, flow through `RuleResult.CisMappings`, and are attached to `Finding.CisMappings` in both the full audit and single-rule explain paths. Evidence exports preserve them in CSV, HTML, Markdown, JSON, and STIX formats.

## Current Limitations

- It is a deterministic rule-based assistant, not an LLM-backed conversational system.
- Scanner parsers are pragmatic and command-output based, so unusual distro output may need parser tests and adjustments.
- Capability status reports command availability and permission visibility, not semantic completeness of every data source.
- Some findings are posture checks rather than proof of compromise.
- Process names and firewall details may require elevated privileges depending on the host.
- Deterministic follow-up questions (changes, critical explanations, category filtering, remediation prioritization, interactive remediation, and suppressed listing) operate on the last audit result without re-running scans. They require a prior audit context; when context is missing they return guidance or fall back to a targeted audit for category-filter queries.
- New suppressions are fingerprint-scoped when the selected finding has a fingerprint. Older suppressions without fingerprints still match by rule ID and target, so intentional target text changes can require accepting the risk again.
- Command safety labels use conservative keyword heuristics. Unknown means "not classified," not "safe."
- The desktop UI includes a machine-role dropdown for hot-swapping roles without code changes.

## Roadmap

- Add richer follow-up explanation flows that can compare related findings and suggest next triage steps.
- Add a policy editing surface in the Avalonia UI.
- Expand scanner fixtures across more distributions and command variants.
- Add reminder surfaces for upcoming suppression review dates.
- Add a "Fix Selected" quick-action button that invokes the same interactive remediation path as `fix <rule-id>`.

## Implementation Evidence

- [SecurityAgent.cs](../VulcansTrace.Linux.Agent/SecurityAgent.cs)
- [QueryParser.cs](../VulcansTrace.Linux.Agent/Query/QueryParser.cs)
- [ScanData.cs](../VulcansTrace.Linux.Agent/Scanners/ScanData.cs)
- [ScannerCoordinator.cs](../VulcansTrace.Linux.Agent/Scanners/ScannerCoordinator.cs)
- [FirewallScanner.cs](../VulcansTrace.Linux.Agent/Scanners/FirewallScanner.cs)
- [PortScanner.cs](../VulcansTrace.Linux.Agent/Scanners/PortScanner.cs)
- [ServiceScanner.cs](../VulcansTrace.Linux.Agent/Scanners/ServiceScanner.cs)
- [NetworkScanner.cs](../VulcansTrace.Linux.Agent/Scanners/NetworkScanner.cs)
- [SshConfigScanner.cs](../VulcansTrace.Linux.Agent/Scanners/SshConfigScanner.cs)
- [FilePermissionScanner.cs](../VulcansTrace.Linux.Agent/Scanners/FilePermissionScanner.cs)
- [FilesystemAuditScanner.cs](../VulcansTrace.Linux.Agent/Scanners/FilesystemAuditScanner.cs)
- [KernelHardeningScanner.cs](../VulcansTrace.Linux.Agent/Scanners/KernelHardeningScanner.cs)
- [UserAccountScanner.cs](../VulcansTrace.Linux.Agent/Scanners/UserAccountScanner.cs)
- [LoggingAuditScanner.cs](../VulcansTrace.Linux.Agent/Scanners/LoggingAuditScanner.cs)
- [CronJobScanner.cs](../VulcansTrace.Linux.Agent/Scanners/CronJobScanner.cs)
- [PackageVulnerabilityScanner.cs](../VulcansTrace.Linux.Agent/Scanners/PackageVulnerabilityScanner.cs)
- [Security rules](../VulcansTrace.Linux.Agent/Rules/SecurityRules)
- [RuleEvaluationService.cs](../VulcansTrace.Linux.Agent/Rules/RuleEvaluationService.cs)
- [FindingAssemblyService.cs](../VulcansTrace.Linux.Agent/Reports/FindingAssemblyService.cs)
- [AgentResultComposer.cs](../VulcansTrace.Linux.Agent/Reports/AgentResultComposer.cs)
- [AgentLogAnalysisService.cs](../VulcansTrace.Linux.Agent/Reports/AgentLogAnalysisService.cs)
- [AgentResultFinalizer.cs](../VulcansTrace.Linux.Agent/Reports/AgentResultFinalizer.cs)
- [AgentFollowUpService.cs](../VulcansTrace.Linux.Agent/Reports/AgentFollowUpService.cs)
- [FindingExplanationService.cs](../VulcansTrace.Linux.Agent/Reports/FindingExplanationService.cs)
- [SingleRuleExplanationService.cs](../VulcansTrace.Linux.Agent/Reports/SingleRuleExplanationService.cs)
- [LoggingAuditRules.cs](../VulcansTrace.Linux.Agent/Rules/SecurityRules/LoggingAuditRules.cs)
- [CronJobRules.cs](../VulcansTrace.Linux.Agent/Rules/SecurityRules/CronJobRules.cs)
- [PackageVulnerabilityRules.cs](../VulcansTrace.Linux.Agent/Rules/SecurityRules/PackageVulnerabilityRules.cs)
- [AgentViewModel.cs](../VulcansTrace.Linux.Avalonia/ViewModels/AgentViewModel.cs)
- [AgentMessageViewModel.cs](../VulcansTrace.Linux.Avalonia/ViewModels/AgentMessageViewModel.cs)
- [AgentOperationRunner.cs](../VulcansTrace.Linux.Avalonia/ViewModels/AgentOperationRunner.cs)
- [AgentResultPresenter.cs](../VulcansTrace.Linux.Avalonia/ViewModels/AgentResultPresenter.cs)
- [AgentHistoryCoordinator.cs](../VulcansTrace.Linux.Avalonia/ViewModels/AgentHistoryCoordinator.cs)
- [ComplianceScorecardViewModel.cs](../VulcansTrace.Linux.Avalonia/ViewModels/ComplianceScorecardViewModel.cs)
- [RiskScorecardViewModel.cs](../VulcansTrace.Linux.Avalonia/ViewModels/RiskScorecardViewModel.cs)
- [RiskScorecardBuilder.cs](../VulcansTrace.Linux.Agent/Reports/RiskScorecardBuilder.cs)
- [SecurityAgentTests.cs](../VulcansTrace.Linux.Tests/Agent/SecurityAgentTests.cs)
- [ComplianceScorecardBuilderTests.cs](../VulcansTrace.Linux.Tests/Agent/ComplianceScorecardBuilderTests.cs)
- [ScannerParserFixtureTests.cs](../VulcansTrace.Linux.Tests/Agent/ScannerParserFixtureTests.cs)
- [BaselineEntry.cs](../VulcansTrace.Linux.Agent/Baselines/BaselineEntry.cs)
- [IBaselineStore.cs](../VulcansTrace.Linux.Agent/Baselines/IBaselineStore.cs)
- [JsonFileBaselineStore.cs](../VulcansTrace.Linux.Agent/Baselines/JsonFileBaselineStore.cs)
- [BaselineDiffResult.cs](../VulcansTrace.Linux.Agent/Baselines/BaselineDiffResult.cs)
- [RemediationPlanBuilder.cs](../VulcansTrace.Linux.Agent/Remediation/RemediationPlanBuilder.cs)
- [RemediationExecutor.cs](../VulcansTrace.Linux.Agent/Remediation/RemediationExecutor.cs)
- [AutoFixPolicy.cs](../VulcansTrace.Linux.Agent/Remediation/AutoFixPolicy.cs)
- [ProcessRunner.cs](../VulcansTrace.Linux.Agent/Remediation/ProcessRunner.cs)
- [IProcessRunner.cs](../VulcansTrace.Linux.Agent/Remediation/IProcessRunner.cs)
- [RemediationConsoleFormatter.cs](../VulcansTrace.Linux.Agent/Reports/RemediationConsoleFormatter.cs)
- [RemediationPlanValidator.cs](../VulcansTrace.Linux.Agent/Reports/RemediationPlanValidator.cs)
