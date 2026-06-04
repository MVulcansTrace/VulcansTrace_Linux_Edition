# VulcansTrace Linux Edition - Change Summary and Profile Capabilities

This document summarizes the changes added in this branch and describes the
current analysis profiles (Low, Medium, High), including the detectors they
enable and the thresholds they use. It is intended as a concise portfolio
reference and a technical verification checklist.

Last updated: 2026-06-04

## 1) Changes Added (What Was Implemented)

### Detection and analysis
- C2 Channel Detection: tightened grouping (ignore source port) and guarded
  against invalid tolerance values.
  - Code: `VulcansTrace.Linux.Engine/Detectors/C2ChannelDetector.cs`
- Privilege Escalation Detector: refocused on suspicious admin port access
  spikes and sweeps with a per-profile spike window.
  - Code: `VulcansTrace.Linux.Engine/Detectors/PrivilegeEscalationDetector.cs`
- Flag Anomaly Detector: eliminated false positives when TCP flags are missing.
  - Code: `VulcansTrace.Linux.Engine/Detectors/FlagAnomalyDetector.cs`

### Evidence and export formats
- STIX 2.1 export rebuilt: now emits a STIX bundle with identity,
  observed-data, note objects, IP observables, and optional malware hints.
  - Code: `VulcansTrace.Linux.Evidence/Formatters/StixFormatter.cs`
- Trace Map evidence export: when correlated findings are present, the signed ZIP bundle includes `incident-story.md` (human-readable attack-chain narrative) and `trace-map.json` (Cytoscape.js-compatible graph with nodes and edges).
  - Code: `VulcansTrace.Linux.Evidence/Formatters/TraceMapMarkdownFormatter.cs`
  - Code: `VulcansTrace.Linux.Evidence/Formatters/TraceMapJsonFormatter.cs`
  - Code: `VulcansTrace.Linux.Evidence/EvidenceBuilder.cs`
- Evidence bundle validation added to the CLI utility.
  - Code: `tools/TestAnalysis/Program.cs`

### UI and UX
- Timeline visualization: normalized placement, severity-based colors,
  time-range label, and tooltip detail.
  - Code: `VulcansTrace.Linux.Avalonia/ViewModels/TimelineViewModel.cs`
  - Code: `VulcansTrace.Linux.Avalonia/MainWindow.axaml`
  - Code: `VulcansTrace.Linux.Avalonia/MainWindow.axaml.cs`
- Trace Map / Incident Graph: interactive attack-chain visualization on the timeline canvas. Directed correlation edges (escalation, temporal sequence, same-host) are drawn between related findings. Click-to-highlight with BFS chain walking, narrative panel, host-based grouping toggle, and performance guardrail (>100 edges suppresses canvas rendering).
  - Code: `VulcansTrace.Linux.Engine/TraceMapCorrelator.cs`
  - Code: `VulcansTrace.Linux.Avalonia/ViewModels/TimelineViewModel.cs`
  - Code: `VulcansTrace.Linux.Avalonia/MainWindow.axaml.cs`
  - Code: `VulcansTrace.Linux.Evidence/Formatters/TraceMapMarkdownFormatter.cs`
  - Code: `VulcansTrace.Linux.Evidence/Formatters/TraceMapJsonFormatter.cs`
- Dialogs: moved from FluentAvalonia ContentDialog to a native Avalonia Window.
  - Code: `VulcansTrace.Linux.Avalonia/Services/AvaloniaDialogService.cs`

### Dependencies
- Removed FluentAvalonia UI dependency.
- Added `Avalonia.Controls.DataGrid` (11.3.11) for the grid view.
  - Code: `VulcansTrace.Linux.Avalonia/VulcansTrace.Linux.Avalonia.csproj`

### Tests and fixtures
- Updated tests to match the refined detectors and avoid time-window flakiness.
  - Code: `VulcansTrace.Linux.Tests/Detectors/Linux/FlagAnomalyDetectorTests.cs`
  - Code: `VulcansTrace.Linux.Tests/Detectors/PrivilegeEscalationDetectorTests.cs`
  - Code: `VulcansTrace.Linux.Tests/Integration/RealWorldAttackScenarioTests.cs`
  - Code: `VulcansTrace.Linux.Tests/Integration/SentryAnalyzerTests.cs`
- Trace Map tests: correlator confidence levels, BFS chain walking, edge suppression threshold, narrative generation, deterministic edge IDs, JSON/Markdown formatter coverage, and E2E evidence bundle inclusion.
  - Code: `VulcansTrace.Linux.Tests/Engine/TraceMapCorrelatorTests.cs`
  - Code: `VulcansTrace.Linux.Tests/Avalonia/TimelineViewModelTraceMapTests.cs`
  - Code: `VulcansTrace.Linux.Tests/Evidence/TraceMapJsonFormatterTests.cs`
  - Code: `VulcansTrace.Linux.Tests/Evidence/TraceMapMarkdownFormatterTests.cs`
  - Code: `VulcansTrace.Linux.Tests/Evidence/EvidenceBuilderTests.cs`
- Expanded `iptables-attack.log` to reliably trigger visible PortScan findings
  at Medium and High intensity. Low still evaluates the scan, but standalone
  PortScan findings are hidden by the High/Critical visibility filter unless
  correlation escalates them.
  - Fixture: `VulcansTrace.Linux.Tests/Data/Real/Samples/iptables-attack.log`

### Security Agent — File Permission Auditing
- Added `FilePermissionScanner` that uses `stat` to read permission bits, ownership, and existence of sensitive files and directories (`/etc/shadow`, `/etc/passwd`, `/etc/ssh/ssh_host_*_key`, `/root/.ssh`, `/etc/cron.*`, `/var/spool/cron`, `/etc/crontab`, and user SSH directories under `/home`).
- Added 7 file permission rules (`FILE-001` through `FILE-007`) with dual-layer CIS compliance mappings:
  - `FILE-001` — `/etc/shadow` should be `640/600`, root-owned (CIS 6.1)
  - `FILE-002` — `/etc/passwd` should be `644`, root-owned (CIS 6.1)
  - `FILE-003` — SSH host private keys should be `600`, root-owned (CIS 5.2)
  - `FILE-004` — `/root/.ssh` should be `700`; `authorized_keys` should be `600` (CIS 5.2)
  - `FILE-005` — Cron directories should not be world-writable (CIS 6.1)
  - `FILE-006` — `/etc/crontab` should be `644/600`, root-owned (CIS 6.1)
  - `FILE-007` — User SSH directories and `authorized_keys` should be tightly restricted (CIS 5.2)
- Added `AgentIntent.FilePermissionCheck` and `QueryParser` keywords so users can ask "check file permissions".
- Added `filepermission.md` explanation template with remediation steps for all file permission rules.
- Code: `VulcansTrace.Linux.Agent/Scanners/FilePermissionScanner.cs`, `VulcansTrace.Linux.Agent/Rules/SecurityRules/FilePermissionRules.cs`, `VulcansTrace.Linux.Agent/Explanations/Templates/filepermission.md`, `VulcansTrace.Linux.Agent/Query/QueryParser.cs`

### Security Agent — Interactive Remediation And Guided Sessions
- Added `AgentIntent.FixFinding` and `HandleFixFindingAsync` for single-finding remediation previews.
- `QueryParser` recognizes `fix FW-001` / `resolve SSH-003` for single-finding remediation previews and `remediate PORT-002` for persisted guided remediation sessions (`fix ` requires a trailing space so `what should i fix` still routes to `PrioritizeRemediation`).
- `HandleFixFindingAsync` builds a single-section `RemediationPlan`, runs `RemediationPlanValidator` to block risky commands without rollback guidance, and returns an interactive remediation card.
- UI renders preconditions, backup commands, apply commands, rollback commands, and verification commands with the same safety and structural badges used for verification commands.
- Added 10 new tests covering intent parsing, target reference extraction, and all `HandleFixFindingAsync` code paths (no context, no reference, unknown reference, success, validation failure).
- Code: `VulcansTrace.Linux.Agent/Query/AgentIntent.cs`, `VulcansTrace.Linux.Agent/Query/QueryParser.cs`, `VulcansTrace.Linux.Agent/SecurityAgent.cs`, `VulcansTrace.Linux.Avalonia/ViewModels/AgentViewModel.cs`, `VulcansTrace.Linux.Avalonia/AgentView.axaml`, `VulcansTrace.Linux.Tests/Agent/QueryParserTests.cs`, `VulcansTrace.Linux.Tests/Agent/SecurityAgentTests.cs`

### Security Agent — Batch Auto-Fix (CLI)
- Added `--auto-fix`, `--dry-run`, `--yes`, `--allow-restart`, and `--allow-packages` flags to the CLI `audit` command.
- `AutoFixPolicy` defines which `CommandSafety` levels are permitted for automatic execution (`Conservative`, `Standard`, `Aggressive` presets).
- `RemediationPlanBuilder` constructs a plan from all findings; `RemediationPlanValidator` blocks sections lacking rollback guidance.
- `RemediationExecutor` orchestrates backup → apply → verify sequentially, with automatic rollback on apply failure. Cancellation is checked before every command via `ExecuteCommandAsync`.
- `ProcessRunner` feeds commands to bash via stdin instead of `-c "..."` to eliminate shell escaping vulnerabilities (newlines, quotes, backticks, `$()`).
- `CommandSafetyClassifier` labels every extracted command by safety impact and structural patterns (sudo, chains, pipes, redirects, download-and-execute).
- Exit codes combined: audit result (`0` or `2`) and auto-fix result (`0` or `3`) use `Math.Max`, so critical findings are never masked by successful auto-fix.
- Scheduled audits (`schedule run`) also support `--auto-fix` flags when invoked manually.
- Auto-fix services (`IProcessRunner`, `RemediationExecutor`, `RemediationPlanBuilder`) are wired into `AgentFactory` and `AgentServices` for centralized composition and testability.
- 30+ new tests covering policy behavior, executor edge cases, rollback behavior, cancellation mid-execution, process runner timeout, console formatter output, and CLI flow integration.
- Code: `VulcansTrace.Linux.Agent/Remediation/*.cs`, `VulcansTrace.Linux.Cli/Program.cs`, `VulcansTrace.Linux.Agent/AgentFactory.cs`, `VulcansTrace.Linux.Tests/Agent/Remediation/*`, `VulcansTrace.Linux.Tests/Cli/AutoFixCliTests.cs`

### Security Agent — Kernel and System Hardening
- Added `KernelHardeningScanner` that reads 9 sysctl values directly from `/proc/sys/` (fast, no shell), with `sysctl -a` fallback for missing values, and checks Secure Boot via `mokutil --sb-state` with EFI variable fallback.
- Added `KernelParameters` record to `ScanData` with typed fields: `RandomizeVaSpace`, `IpForwardIpv4/Ipv6`, `AcceptRedirectsIpv4/Ipv6`, `AcceptSourceRouteIpv4`, `ModulesDisabled`, `SecureBootEnabled`, `KptrRestrict`, `DmesgRestrict`.
- Added 7 kernel hardening rules (`KERN-001` through `KERN-007`) with dual-layer CIS compliance mappings:
  - `KERN-001` — ASLR fully enabled (`kernel.randomize_va_space >= 2`) (CIS 1.5)
  - `KERN-002` — IP forwarding disabled (IPv4 + IPv6) (CIS 3.1)
  - `KERN-003` — ICMP redirects disabled (IPv4 + IPv6) (CIS 3.1)
  - `KERN-004` — Source routed packets rejected (CIS 3.1)
  - `KERN-005` — Kernel module loading restricted (`kernel.modules_disabled != 0`); role-aware severity: High on Server, Medium on Workstation (CIS 1.4)
  - `KERN-006` — Secure Boot enabled; returns `NotApplicable` on BIOS/legacy systems where Secure Boot is unavailable (CIS 1.4)
  - `KERN-007` — Kernel pointer and dmesg exposure restricted (`kptr_restrict >= 1`, `dmesg_restrict == 1`) (CIS 1.5)
- Added `AgentIntent.KernelCheck` and `QueryParser` keywords so users can ask "check my kernel hardening".
- Added `kernel.md` explanation template with remediation steps for all kernel hardening rules.
- Added `RuleStatus.NotApplicable` for hardware-dependent checks that do not apply to the current system (e.g., Secure Boot on BIOS). `BuildSummary` reports not-applicable counts in the audit summary.
- Code: `VulcansTrace.Linux.Agent/Scanners/KernelHardeningScanner.cs`, `VulcansTrace.Linux.Agent/Rules/SecurityRules/KernelHardeningRules.cs`, `VulcansTrace.Linux.Agent/Explanations/Templates/kernel.md`, `VulcansTrace.Linux.Agent/Query/QueryParser.cs`, `VulcansTrace.Linux.Agent/SecurityAgent.cs`

### Security Agent — User & Account Auditing
- Added `UserAccountScanner` that reads `/etc/passwd`, `/etc/shadow`, `/etc/login.defs`, PAM password-stack configs (`common-password`, `system-auth`, `password-auth`, `/etc/security/pwquality.conf`), PAM auth-stack configs (`common-auth`, `/etc/pam.d/sshd`), and `/etc/security/faillock.conf`. Note: only local files are scanned; LDAP/NIS/AD users are not covered.
- Added `UserAccount`, `ShadowEntry`, `LoginDefs`, and `PamConfig` records to `ScanData`.
- Added 10 user account rules (`USER-001` through `USER-010`) with dual-layer CIS compliance mappings:
  - `USER-001` — Only root should have UID 0 (CIS 6.2)
  - `USER-002` — Empty or unset password hashes flagged; locked interactive accounts flagged at lower severity (CIS 5.4)
  - `USER-003` — Password aging enforces `PASS_MAX_DAYS <= 90`, `PASS_MIN_DAYS >= 1`, `PASS_WARN_AGE >= 7`, plus per-user shadow checks (CIS 5.4)
  - `USER-004` — PAM password-stack must include a complexity module (`pam_pwquality.so`, `pam_cracklib.so`, or `pam_passwdqc.so`) (CIS 5.4)
  - `USER-005` — Inactive or locked interactive accounts (UID >= 1000) with expired expiry dates flagged (CIS 6.2)
  - `USER-006` — Each UID should be unique (CIS 6.2)
  - `USER-007` — Regular interactive accounts should have an existing home directory (CIS 6.2)
  - `USER-008` — PAM faillock must be configured in every auth stack (`preauth` + `authfail`) with a readable `faillock.conf` (CIS 5.3)
  - `USER-009` — PAM password quality must enforce `minlen >= 14`, `minclass >= 3`, and credit requirements (`dcredit`, `ucredit`, `lcredit`, `ocredit`) (CIS 5.4)
  - `USER-010` — PAM auth stack must place `required`/`requisite`/`binding` or bracketed controls before any `sufficient` module in every file (CIS 5.3)
- `EmptyPasswordRule` returns `NotApplicable` when `/etc/shadow` is unreadable (non-root), matching `KERN-006` behavior.
- `PamPasswordComplexityRule` only inspects PAM lines in the `password` management stack.
- `PamAuthRequiredRule` evaluates auth stack ordering per-file using `PamConfig.RawLinesByFile`; fails if any single file has `sufficient` before mandatory controls.
- `MissingHomeDirectoryRule` uses pre-collected `HomeDirectoryExists` from the scanner instead of calling `Directory.Exists()` at evaluation time.
- Added `AgentIntent.UserAccountCheck` and `QueryParser` keywords so users can ask "check my user accounts".
- Added `useraccount.md` explanation template with remediation steps for all user account rules.
- Code: `VulcansTrace.Linux.Agent/Scanners/UserAccountScanner.cs`, `VulcansTrace.Linux.Agent/Rules/SecurityRules/UserAccountRules.cs`, `VulcansTrace.Linux.Agent/Explanations/Templates/useraccount.md`, `VulcansTrace.Linux.Agent/Query/QueryParser.cs`, `VulcansTrace.Linux.Agent/SecurityAgent.cs`

### Security Agent — Filesystem Auditing
- Added `FilesystemAuditScanner` that runs targeted `find` commands to discover world-writable files, SUID/SGID binaries, unowned files, world-writable directories without sticky bit, and `/tmp` mount options.
- Added 5 filesystem audit rules (`FSYS-001` through `FSYS-005`) with dual-layer CIS compliance mappings:
  - `FSYS-001` — World-writable files outside expected temporary paths (CIS 6.1.9)
  - `FSYS-002` — Unexpected SUID/SGID binaries outside the known-good full-path whitelist (CIS 6.1.12)
  - `FSYS-003` — Unowned files (no valid user or group) (CIS 6.1.11)
  - `FSYS-004` — World-writable directories without sticky bit (CIS 6.1.10)
  - `FSYS-005` — `/tmp` should be a separate mount with `noexec`, `nosuid`, and `nodev` (CIS 1.1.2)
- `AgentIntent.FilesystemAuditCheck` and `QueryParser` keywords so users can ask "check my filesystem" or "any SUID binaries?".
- Added `FilesystemAuditEntry` record to `ScanData` with `Path`, `Mode`, `Owner`, `Group`, and `AuditCategory`.
- Added `TmpMountOptions` and `TmpMountTarget` to `ScanData` for `/tmp` mount analysis.
- SUID whitelist uses **full paths** (not filenames) to prevent bypass by naming a backdoor after a whitelisted binary.
- Fingerprints are stable: rules sort findings by path and use the first path only in `Target`, with count in `Variables`.
- Added `filesystemaudit.md` explanation template with remediation steps for all filesystem audit rules.
- Code: `VulcansTrace.Linux.Agent/Scanners/FilesystemAuditScanner.cs`, `VulcansTrace.Linux.Agent/Rules/SecurityRules/FilesystemAuditRules.cs`, `VulcansTrace.Linux.Agent/Explanations/Templates/filesystemaudit.md`, `VulcansTrace.Linux.Agent/Scanners/ScanData.cs`, `VulcansTrace.Linux.Agent/Query/QueryParser.cs`

### Security Agent — Logging & Auditing
- Added `LoggingAuditScanner` that checks rsyslog and journald service status, reads auditd rules via `auditctl -l` with fallback to `/etc/audit/audit.rules`, checks logrotate configuration, and detects central log forwarding via rsyslog (`@`/`@@` targets) and journald (`ForwardToSyslog=yes`).
- Added `LoggingAuditConfig` record to `ScanData` with typed fields: `RsyslogActive`, `JournaldActive`, `AuditdActive`, `AuditdRulesConfigured`, `LogRotationConfigured`, `CentralForwardingConfigured`, `AuditdRules`, `ForwardingTargets`, `ReadWarning`.
- Added 7 logging/audit rules (`LOG-001` through `LOG-007`) with dual-layer CIS compliance mappings:
  - `LOG-001` — At least one system logging service (rsyslog or journald) should be active (CIS 8.1)
  - `LOG-002` — auditd should be installed and active (CIS 8.2)
  - `LOG-003` — auditd should have active rules monitoring key security events (CIS 8.2)
  - `LOG-004` — Log rotation should be configured via logrotate (CIS 8.3)
  - `LOG-005` — Central log forwarding should be configured (rsyslog remote or journald ForwardToSyslog); exempt on Workstation, DevMachine, LabBox, and Router (CIS 8.4)
  - `LOG-006` — auditd should monitor privilege escalation syscalls (`setuid`, `setgid`, etc.) (CIS 8.2)
  - `LOG-007` — Central forwarding should use TCP (`@@` target) rather than UDP (`@`) for reliability (CIS 8.4)
- `LOG-003` and `LOG-006` return `NotApplicable` when `ReadWarning` is set (partial scanner failure such as permission denied) so they do not produce false negatives on incomplete data.
- `IsForwardingTarget` filters rsyslog control directives (`@include`, `@version`, `@moduleLoad`, etc.) to prevent false positives.
- `IsActualAuditdRule` distinguishes real audit rules (`-w`, `-a`, `-A`) from control directives (`-D`, `-b`, `-f`, etc.).
- `CheckCentralForwarding` uses `HashSet<string>` for deduplication and supports both rsyslog config files and journald.conf.
- Added `AgentIntent.LoggingAuditCheck` and `QueryParser` keywords (`logging`, `log`, `rsyslog`, `journald`, `auditd`, `logrotate`, `forwarding`, `syslog`) so users can ask "check my logging".
- Added `loggingaudit.md` explanation template with remediation steps for all logging/audit rules.
- Code: `VulcansTrace.Linux.Agent/Scanners/LoggingAuditScanner.cs`, `VulcansTrace.Linux.Agent/Rules/SecurityRules/LoggingAuditRules.cs`, `VulcansTrace.Linux.Agent/Explanations/Templates/loggingaudit.md`, `VulcansTrace.Linux.Agent/Query/QueryParser.cs`, `VulcansTrace.Linux.Agent/SecurityAgent.cs`

### Security Agent — Cron Job Auditing
- Added `CronJobScanner` that reads and parses system crontabs (`/etc/crontab`, `/etc/cron.d/*`), user crontabs (`/var/spool/cron/crontabs/*`, `/var/spool/cron/*` for RHEL/CentOS/Fedora), and cron script directories (`cron.daily`, `cron.hourly`, `cron.weekly`, `cron.monthly`). Uses `stat` for script permissions.
- Added `CronJobEntry` record to `ScanData` with `SourceFile`, `Schedule`, `Command`, `RunAsUser`, `IsScript`, `ScriptPermissions`, `ScriptOwner`, and `ScriptGroup`.
- Added 3 cron job rules (`CRON-001` through `CRON-003`) with dual-layer CIS compliance mappings:
  - `CRON-001` — Suspicious cron commands (reverse shells, network downloaders, temp paths, encoded payloads). Uses word-boundary-aware pattern matching to reduce false positives (CIS 6.1)
  - `CRON-002` — Cron scripts should not be world-writable; setuid/setgid bits escalated to `Critical` severity (CIS 6.1)
  - `CRON-003` — Root cron jobs should not reference non-root user directories (`/home/` or `~username`) (CIS 6.2)
- All cron rules return `NotApplicable` when no cron data is available.
- `AgentIntent.CronJobCheck` and `QueryParser` keywords (`cron`, `crontab`, `scheduled job`, `cron job`) so users can ask "check my cron jobs".
- Added `cron.md` explanation template with remediation steps for all cron job rules.
- 30+ new tests covering scanner parsing, word-boundary matching, setuid detection, tilde-user path detection, multiple-match reporting, and NotApplicable behavior.
- Code: `VulcansTrace.Linux.Agent/Scanners/CronJobScanner.cs`, `VulcansTrace.Linux.Agent/Rules/SecurityRules/CronJobRules.cs`, `VulcansTrace.Linux.Agent/Explanations/Templates/cron.md`, `VulcansTrace.Linux.Agent/Query/QueryParser.cs`, `VulcansTrace.Linux.Agent/SecurityAgent.cs`, `VulcansTrace.Linux.Agent/Query/AgentIntent.cs`

### Security Agent — Package Vulnerability Scanning
- Added `PackageVulnerabilityScanner` that enumerates installed packages via `dpkg-query`, detects pending security updates via `apt list --upgradeable` and `apt-cache policy` (classifying updates from security repositories), optionally enriches findings with specific CVE IDs when `debsecan` is installed, and checks `unattended-upgrades` configuration.
- Added `InstalledPackage`, `VulnerablePackage`, and `PackageVulnerabilityStatus` records to `ScanData` with typed fields: `Name`, `Version`, `Architecture`, `InstalledVersion`, `AvailableVersion`, `IsSecurityUpdate`, `CveIds`, `Source`, `PackagesReadable`, `UnattendedUpgradesConfigured`, `UnattendedUpgradesEnabled`, `CveDataAvailable`.
- Added 3 package vulnerability rules (`PKG-VULN-001` through `PKG-VULN-003`) with dual-layer CIS compliance mappings:
  - `PKG-VULN-001` — Pending security updates should be applied promptly; severity escalates to `Critical` when 5+ security updates are pending (CIS 1.9)
  - `PKG-VULN-002` — Automatic security updates via `unattended-upgrades` should be configured (CIS 1.9)
  - `PKG-VULN-003` — Known CVEs affecting installed packages should be tracked and patched; returns `NotApplicable` when CVE enrichment data (debsecan) is unavailable, preventing false confidence (no direct CIS mapping)
- All package vulnerability rules return `NotApplicable` when package data is unreadable (dpkg-query failed or permission denied), matching the behavior of `LoggingAuditRules` and `CronJobRules`.
- `AgentIntent.PackageVulnerabilityCheck` and `QueryParser` keywords (`package`, `vulnerability`, `cve`, `security update`, `apt`, `upgradeable`, `patch`) so users can ask "check package vulnerabilities".
- Added `packagevulnerability.md` explanation template with remediation steps for all package vulnerability rules.
- Scanner handles edge cases robustly: OCE during optional debsecan enrichment does not discard core dpkg/apt data; empty dpkg-query output on success is distinguished from command failure; per-package `apt-cache policy` failures emit warnings; `CheckUnattendedUpgrades` uses a simple line-scan parser instead of fragile block-state tracking.
- CVEs for packages without upgradeable versions in configured repos are still reported (with `Source = "debsecan (fix may require repository reconfiguration)"`), preventing silent data loss.
- Added `FindingCategories.PackageVulnerability` constant for consistency with other rule families.
- 20+ new tests covering scanner parser fixtures (dpkg, apt, apt-cache policy, debsecan), rule behavior (NotApplicable on missing data, severity escalation, CVE availability gating), and query parser keyword matching.
- Code: `VulcansTrace.Linux.Agent/Scanners/PackageVulnerabilityScanner.cs`, `VulcansTrace.Linux.Agent/Rules/SecurityRules/PackageVulnerabilityRules.cs`, `VulcansTrace.Linux.Agent/Explanations/Templates/packagevulnerability.md`, `VulcansTrace.Linux.Agent/Query/QueryParser.cs`, `VulcansTrace.Linux.Agent/Query/AgentIntent.cs`, `VulcansTrace.Linux.Agent/SecurityAgent.cs`, `VulcansTrace.Linux.Core/FindingCategories.cs`

### Security Agent — SSH Daemon Auditing
- Added `SshConfigScanner` that reads `sshd -T` output (with fallback to `/etc/ssh/sshd_config` plus `Include` directives).
- Added 8 SSH hardening rules (`SSH-001` through `SSH-008`) with dual-layer CIS compliance mappings:
  - `SSH-001` — `PermitRootLogin` should be disabled or `prohibit-password` (CIS 5.4)
  - `SSH-002` — `PasswordAuthentication` should be disabled (CIS 6.3)
  - `SSH-003` — `MaxAuthTries` should be 4 or lower (CIS 6.3)
  - `SSH-004` — SSH Protocol 1 should not be enabled (CIS 4.8)
  - `SSH-005` — `PermitEmptyPasswords` should be disabled (CIS 5.2)
  - `SSH-006` — `PubkeyAuthentication` should be enabled (CIS 6.3)
  - `SSH-007` — `X11Forwarding` should be disabled on servers (CIS 4.8)
  - `SSH-008` — `UsePAM` should be enabled to enforce local PAM policies (CIS 5.2)
- `SshX11ForwardingRule` is role-aware: returns `Pass` on `Workstation` where X11 forwarding may be intentional.
- Added `AgentIntent.SshCheck` and `QueryParser` keywords so users can ask "check my SSH".
- Added `ssh.md` explanation template with remediation steps for all SSH rules.
- Code: `VulcansTrace.Linux.Agent/Scanners/SshConfigScanner.cs`, `VulcansTrace.Linux.Agent/Rules/SecurityRules/SshRules.cs`, `VulcansTrace.Linux.Agent/Explanations/Templates/ssh.md`

### Security Agent — Container & Kubernetes Security Scanner
- Added `ContainerScanner` that scans local container runtime state via `docker ps` + `docker inspect` (with `crictl` fallback), detecting running containers, privileged mode, `latest` tags, Docker socket exposure/mounts, known risky base-image hints from local image metadata, and containerd namespace isolation. Per-element try/catch in parsers emits warnings instead of silently swallowing malformed entries.
- Added `KubernetesScanner` that scans Kubernetes pods via `kubectl get pods --all-namespaces -o json` when a kubeconfig is present. Supports the `$KUBECONFIG` environment variable and uses the configured cluster context. Detects privileged containers, `hostNetwork`/`hostPID`/`hostIPC` sharing, root containers, and missing security context hardening (`allowPrivilegeEscalation: false`, `readOnlyRootFilesystem`, dropped capabilities, confined seccomp profile). Pod-level `securityContext` is inherited by containers with container-level overrides respected.
- Added 5 container security rules (`CTR-001` through `CTR-005`) with dual-layer CIS compliance mappings:
  - `CTR-001` — Privileged containers should not be running (CIS Docker Benchmark 5.4)
  - `CTR-002` — Container images should not use the `latest` tag (CIS Docker Benchmark 4.1)
  - `CTR-003` — Docker socket should not be exposed on the host or mounted into containers (CIS Docker Benchmark 5.25)
  - `CTR-004` — Containerd should use explicit namespaces rather than only the default (CIS Containerd Benchmark 1.1)
  - `CTR-005` — Container images should not use known risky base-image hints (CIS Docker Benchmark 4.1)
- Added 4 Kubernetes security rules (`K8S-001` through `K8S-004`) with dual-layer CIS compliance mappings:
  - `K8S-001` — Pods should not run privileged containers (CIS Kubernetes Benchmark 5.2.1)
  - `K8S-002` — Pods should not use `hostNetwork`, `hostPID`, or `hostIPC` (CIS Kubernetes Benchmark 5.2.4)
  - `K8S-003` — Containers should run as non-root (CIS Kubernetes Benchmark 5.2.6)
  - `K8S-004` — Containers should have hardened security contexts, including disabled privilege escalation and confined seccomp (CIS Kubernetes Benchmark 5.2.7)
- Added `ContainerRuntimeInfo`, `ContainerInfo`, `KubernetesPodInfo`, and `K8sContainerInfo` records to `ScanData` / `ScanDataBuilder`.
- Added `FindingCategories.Container` and `FindingCategories.Kubernetes` constants.
- Added `AgentIntent.ContainerCheck` and `AgentIntent.KubernetesCheck` with `QueryParser` keywords (`container`, `docker`, `kubernetes`, `k8s`, `pod`, `pods`).
- Added container/kubernetes intent filtering in `RuleEvaluationService.FilterRulesByIntent`.
- Added follow-up intent mapping in `AgentFollowUpService.InferIntentFromCategory` for `ContainerCheck` and `KubernetesCheck`.
- Added result composer labels (`Container check`, `Kubernetes check`) in `AgentResultComposer.BuildSummary`.
- Added `container.md` and `kubernetes.md` explanation templates with remediation steps.
- Scanner failures (missing docker/crictl/ctr/kubectl, permission denied, malformed JSON) are reported as warnings without crashing the agent.
- All container and Kubernetes rules return `Pass` when the respective runtime is unavailable, preventing false positives on non-containerized hosts.
- 20+ new tests covering scanner parser fixtures (docker ps, docker inspect JSON, crictl JSON, ctr namespace, kubectl pods JSON), rule behavior (privileged, latest tag, socket exposure/mount, known risky base hints, namespace defaults, pod security context inheritance, root detection, capability/seccomp checks), intent parsing, UI audit-state routing, and `RuleCatalogTests` count update.
  - Code: `VulcansTrace.Linux.Agent/Scanners/ContainerScanner.cs`, `VulcansTrace.Linux.Agent/Scanners/KubernetesScanner.cs`, `VulcansTrace.Linux.Agent/Rules/SecurityRules/ContainerRules.cs`, `VulcansTrace.Linux.Agent/Rules/SecurityRules/KubernetesRules.cs`, `VulcansTrace.Linux.Agent/Explanations/Templates/container.md`, `VulcansTrace.Linux.Agent/Explanations/Templates/kubernetes.md`, `VulcansTrace.Linux.Agent/Query/QueryParser.cs`, `VulcansTrace.Linux.Agent/Query/AgentIntent.cs`, `VulcansTrace.Linux.Agent/SecurityAgent.cs`, `VulcansTrace.Linux.Core/FindingCategories.cs`

### Security Agent — CIS Benchmark Mapping
- All 76 agent rules now carry dual-layer CIS compliance mappings:
  - **CIS Controls v8** (organizational): e.g., `CIS 4.5`, `CIS 5.4`, `CIS 6.3`
  - **CIS Ubuntu 24.04 LTS Benchmark** (technical): e.g., `5.2.7 Ensure SSH root login is disabled`
  - `CisBenchmarkMapping` record extended with optional `BenchmarkReference` field
  - Mappings flow through full audits, single-rule explanations, crashes, and policy-disabled results
  - Evidence exports preserve mappings in CSV, HTML, Markdown, JSON, and STIX formats
  - HTML and Markdown compliance-context deduplication changed from `ControlId`-only grouping to `Distinct()` so unique rationale per rule is preserved
  - Code: `VulcansTrace.Linux.Core/CisBenchmarkMapping.cs`, `VulcansTrace.Linux.Agent/Rules/SecurityRules/*.cs`, `VulcansTrace.Linux.Evidence/Formatters/*.cs`

### Recurring Audit Scheduling
- Headless CLI (`VulcansTrace.Linux.Cli`) with `audit` and `schedule` subcommands for running audits and managing recurring schedules without the desktop UI.
  - Commands: `list`, `add`, `edit`, `delete`, `enable`, `disable`, `run`, `install-cron`, `uninstall-cron`.
  - Exit codes: 0 (success), 1 (error), 2 (success with critical findings), 3 (auto-fix executed but some remediation commands failed).
  - Code: `VulcansTrace.Linux.Cli/Program.cs`
- GUI Schedule Editor (`ScheduleView`) in the Avalonia UI with a DataGrid, Add/Edit/Delete/Run Now/Install Cron actions, and cron status indicators.
  - Code: `VulcansTrace.Linux.Avalonia/Views/ScheduleView.axaml`, `VulcansTrace.Linux.Avalonia/ViewModels/ScheduleViewModel.cs`, `ScheduleEditWindow.axaml`
- System crontab integration (`CrontabManager`) reads and writes the user crontab, using a unique marker prefix (`# VT-SCH-7a3f9e2d schedule-id=`) to avoid collision with non-VulcansTrace entries.
  - Code: `VulcansTrace.Linux.Agent/Scheduling/CrontabManager.cs`
- Cron expression validation (`CronExpressionValidator`) ensures 5-field syntax before saving.
  - Code: `VulcansTrace.Linux.Agent/Scheduling/CronExpressionValidator.cs`
- Schedule persistence via `JsonFileScheduleStore` (atomic temp-file writes to `~/.config/VulcansTrace/schedules.json`) and `InMemoryScheduleStore` fallback.
  - Code: `VulcansTrace.Linux.Agent/Scheduling/JsonFileScheduleStore.cs`, `InMemoryScheduleStore.cs`
- Fingerprint-aware new-critical-only diffing compares current audit critical findings against the previous `AuditHistoryEntry` and only notifies when new critical fingerprints appear. Pre-fingerprint history entries are handled gracefully to avoid upgrade-storm notifications.
  - Code: `VulcansTrace.Linux.Cli/Program.cs`, `VulcansTrace.Linux.Avalonia/ViewModels/ScheduleViewModel.cs`
- Machine role picker dropdown in the Avalonia UI allows hot-swapping roles without code changes.
  - Code: `VulcansTrace.Linux.Avalonia/ViewModels/MainViewModel.cs`, `AgentViewModel.cs`

### Security Agent — Remediation Session Notes + Evidence Attachments
- Added `SessionNote` record to `RemediationSession` with `Text`, `CreatedAtUtc`, optional `RuleId`, and `EvidenceLinks`.
- Added `SessionNoteAdded` and `StepNoteAdded` to `RemediationSessionEventType` for immutable timeline recording.
- Added `GuidedRemediationService.AddSessionNote` and `AddStepNote` — append-only, validates the session exists, guards against null/empty rule IDs and unknown steps, and returns concise confirmation results.
- Added `AgentIntent.AddSessionNote` and `AgentIntent.AddStepNote` with `QueryParser` support for natural-language patterns such as `add note to session abc12345 ...` and `note for step FW-001 in session abc12345 ...`.
- `QueryParser` extracts session IDs for both note intents using the existing `SessionIdPattern` regex, avoiding unreliable hex-word heuristics that could steal CVE IDs or hashes from note text.
- `SecurityAgent.AskAsync` routes note intents through `GuidedRemediationService` and strips evidence syntax from note text via `ExtractEvidenceLinks`, which uses `Regex.Replace` callbacks to collect bracket (`[ref]`) and backtick (`` `ref` ``) references while removing the wrapper syntax from the stored text.
- `RemediationMarkdownFormatter` renders a `## Notes` section in exported session reports, grouping session notes under `### Session Notes` and step notes under `### Step Notes` (organized by rule ID), with timestamps, text, and bulleted evidence links.
- `AgentResultPresenter` renders a single-line confirmation message for `AddSessionNote`/`AddStepNote` results instead of falling through to the full remediation plan summary.
- 10+ new integration and edge-case tests covering full `AskAsync` routing, prefix stripping, empty note text, evidence syntax extraction, confidence/ambiguity scoring, and collision avoidance.
- Code: `VulcansTrace.Linux.Agent/Sessions/RemediationSession.cs`, `VulcansTrace.Linux.Agent/Reports/GuidedRemediationService.cs`, `VulcansTrace.Linux.Agent/SecurityAgent.cs`, `VulcansTrace.Linux.Agent/Query/QueryParser.cs`, `VulcansTrace.Linux.Agent/Query/AgentIntent.cs`, `VulcansTrace.Linux.Agent/Reports/RemediationMarkdownFormatter.cs`, `VulcansTrace.Linux.Avalonia/ViewModels/AgentResultPresenter.cs`, `VulcansTrace.Linux.Tests/Agent/SecurityAgentTests.cs`, `VulcansTrace.Linux.Tests/Agent/QueryParserTests.cs`

### Security Agent — Remediation Session Resume / History Browser
- Added `AgentIntent.ListRemediationSessions` and `AgentIntent.ResumeRemediation` with `QueryParser` support for `list my sessions`, `show sessions`, and `resume session <id>`.
- `GuidedRemediationService` now exposes `ListSessionsAsync`, `LoadSessionAsync`, and `DeleteSessionAsync` for full session store lifecycle management.
- `IAgent` interface extended with `ListRemediationSessionsAsync`, `LoadRemediationSessionAsync`, and `DeleteRemediationSessionAsync`.
- `RemediationSessionEventType` expanded with `SessionResumed` for audit traceability when sessions are reopened.
- Avalonia UI **Remediation Sessions** expander lists all persisted sessions with ID, status, rule ID, and creation time. Select a session and click **Resume** to reload it into chat, or **Delete** to remove it.
- CLI adds `session list`, `session show`, and `session delete` subcommands for headless session management.
- The session browser refreshes after session-producing operations so create, resume, verify, export, and delete actions stay visible without reopening the panel.
- `BuildSessionResult` accepts an optional `intent` parameter so resumed sessions report `ResumeRemediation` instead of hardcoding `StartRemediation`.
- Code: `VulcansTrace.Linux.Agent/Query/AgentIntent.cs`, `VulcansTrace.Linux.Agent/Query/QueryParser.cs`, `VulcansTrace.Linux.Agent/SecurityAgent.cs`, `VulcansTrace.Linux.Agent/IAgent.cs`, `VulcansTrace.Linux.Agent/Reports/GuidedRemediationService.cs`, `VulcansTrace.Linux.Agent/Sessions/RemediationSession.cs`, `VulcansTrace.Linux.Avalonia/ViewModels/AgentViewModel.cs`, `VulcansTrace.Linux.Avalonia/AgentView.axaml`, `VulcansTrace.Linux.Cli/Program.cs`, `VulcansTrace.Linux.Avalonia/ViewModels/AgentOperationRunner.cs`

### Notifications
- `NotifySendNotificationService` — Linux desktop notifications via `notify-send`.
  - Code: `VulcansTrace.Linux.Agent/Notifications/NotifySendNotificationService.cs`
- `EmailNotificationService` — SMTP email notifications with TLS support and configurable credentials via environment variables.
  - Code: `VulcansTrace.Linux.Agent/Notifications/EmailNotificationService.cs`
- `WebhookNotificationService` — HTTP POST JSON notifications with 3 retries and exponential backoff for transient failures (5xx, timeouts, connection errors). Implements `IDisposable`.
  - Code: `VulcansTrace.Linux.Agent/Notifications/WebhookNotificationService.cs`
- `INotificationService.NotifyAsync` marked `[Obsolete]` — unused, prefer `NotifyCriticalFindingsAsync`.
  - Code: `VulcansTrace.Linux.Agent/Notifications/INotificationService.cs`

### Packaging
- `scripts/publish-cli.sh` builds a self-contained `linux-x64` binary.
  - Script: `scripts/publish-cli.sh`

### Robustness and Security Hardening
- `AgentServices` implements `IDisposable` and properly disposes all store and notification service instances.
- `JsonFileScheduleStore` uses atomic file writes (temp file + move) to prevent JSON corruption on power loss.
- `InMemoryScheduleStore` is now thread-safe with `ReaderWriterLockSlim`.
- `CrontabManager.ReadCrontab` handles multiple cron implementations' empty-crontab messages.
- `CrontabManager.WriteCrontab` reads stderr asynchronously before `WaitForExit()` to prevent deadlocks on large stderr output.
- `CrontabManager.Install` rejects disabled schedules.
- CLI `ParseArg`/`TryParseArg` reject values starting with `--` to prevent flags from being consumed as values.
- Schedule name deduplication (case-insensitive) in CLI and GUI.
- `VT_EMAIL_NO_SSL` parsing supports `1`, `true`, and `yes` as disable-SSL values.
- `LastRunUtc` displayed with explicit `UTC` label in CLI list output.
- `ScheduleViewModel.Refresh` preserves DataGrid selection by ID across reloads.

### MITRE ATT&CK Navigator Layer Export
- Added `MitreTechnique` record to Core with `TechniqueId`, `TechniqueName`, `Tactic`, and `WhyItMatters` fields, with validation to prevent empty IDs.
- Added `MitreTechniques` to `Finding`, `IRule`, and `RuleResult` so every detection and rule can carry MITRE context.
- `MitreLayerBuilder` constructs Navigator-compatible layer JSON (format v4.5) with deterministic tactic-specific coverage aggregation, observed-finding scoring, and overridable version fields.
- All 13 engine detectors and all 12 security rule files now carry static `s_mitreTechniques` mappings.
- Evidence formatters (HTML, Markdown, CSV, STIX) include MITRE technique columns and fields.
- CLI `--output-mitre` flag exports a combined Navigator layer from configured detector/rule coverage plus any observed agent and engine findings.
- `EvidenceBuilder` automatically includes `mitre-navigator-layer.json` in every signed evidence ZIP.
- `RemediationSection` carries `MitreTechniques` for threat-contextualized remediation planning.
- Avalonia UI Findings and Rules DataGrids expose a **MITRE ATT&CK** column with searchable/displayable technique summaries.
- `RuleCatalogItem` and `RulesCatalog` flow MITRE techniques through the catalog and include them in search.
- 30+ new tests: `MitreTechniqueTests`, `MitreLayerBuilderTests` (empty, single, aggregate, dedup, gradient, custom name), `DetectorMitreMappingTests` (reflection-based static field verification), and formatter inclusion tests.
  - Code: `VulcansTrace.Linux.Core/MitreTechnique.cs`, `VulcansTrace.Linux.Evidence/MitreLayerBuilder.cs`, `VulcansTrace.Linux.Cli/Program.cs`, `VulcansTrace.Linux.Evidence/EvidenceBuilder.cs`, `VulcansTrace.Linux.Agent/Remediation/RemediationPlan.cs`, `VulcansTrace.Linux.Avalonia/MainWindow.axaml`, `VulcansTrace.Linux.Agent/Rules/RuleCatalogItem.cs`, `VulcansTrace.Linux.Agent/Rules/RulesCatalog.cs`, `VulcansTrace.Linux.Tests/Core/MitreTechniqueTests.cs`, `VulcansTrace.Linux.Tests/Evidence/MitreLayerBuilderTests.cs`, `VulcansTrace.Linux.Tests/Engine/DetectorMitreMappingTests.cs`

### Documentation
- Portfolio and technical docs aligned to actual behavior and formats.
  - Docs: `README.md`, `docs/portfolio/` (15 implementation portfolios),
    `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, `docs/USAGE.md`,
    `docs/DEVELOPMENT.md`, `docs/HMAC_EVIDENCE.md`, `docs/SECURITY_AGENT.md`

### Live Stream / Real-Time Kernel Telemetry
- Added live stream pipeline that captures network events directly from the Linux kernel and runs the detector pipeline in real time.
- **Event sources:**
  - `SyntheticEventSource` — generates realistic traffic without privileges (port scans, beaconing, floods).
  - `PacketCaptureEventSource` — `AF_PACKET` raw socket with classic BPF filter (`SO_ATTACH_FILTER`), parses IP/TCP/UDP headers via P/Invoke to `libc`.
  - `NflogEventSource` — `AF_NETLINK` NFLOG group binding through `NFULNL_MSG_CONFIG`, parses structured netlink attributes including kernel timestamps.
- **Pipeline:** `LiveStreamWindow` with dual eviction (60 s / 10 000 events); dedicated `SentryAnalyzer` instance to avoid concurrency conflicts with batch analysis; `LiveStreamAnalyzer` deduplicates findings by fingerprint with 5-minute TTL; completed results flow through a bounded `DropOldest(64)` channel so stale UI updates do not stall analysis; live findings are capped at 1 000 (FIFO eviction).
- **UI:** Live Stream tab with source selection, privilege detection, live metrics, async stop (`StopAsync()` via `AsyncRelayCommand`), and `LiveResultReceived` wired into the main findings grid.
- **Structured event path:** Live events bypass `FormatAsIptablesLog` / `LogNormalizer` round-trip and feed directly into `SentryAnalyzer.Analyze(IReadOnlyList<UnifiedEvent>)`.
- **Action metadata:** Live events tagged `CAPTURED` (packet capture) or `LOGGED` (NFLOG) instead of `UNKNOWN`.
- **30 bug fixes** during code review: correct `AF_NETLINK` family, flat attribute flags, NFLOG payload/HWADDR/UID constants, `NFULNL_COPY_PACKET` mode request, double-close race, intensity threading, async stop, bounded findings, IDisposable caching, dedicated analyzer, result channel backpressure, realistic TTL, NFLOG timestamp parsing, kernel source fault surfacing, capability-aware source availability, retained parse-error samples, null guards, send errno handling, BPF length guards, delay clamping, structured overload, `LiveResultReceived` wiring, source name constants, and focused tests (VM, parser, config, formatter, stress).
- Code: `VulcansTrace.Linux.Engine/Live/*.cs`, `VulcansTrace.Linux.Avalonia/ViewModels/LiveStreamViewModel.cs`, `VulcansTrace.Linux.Avalonia/Views/LiveStreamView.axaml`, `VulcansTrace.Linux.Tests/Engine/Live/*`

### Tooling
- CLI test runner supports `--intensity`, `--all`, `--export`.
  - Tool: `tools/TestAnalysis/Program.cs`

### CIS Compliance Scorecard
- Added `ComplianceScorecardBuilder` implementing `IComplianceScorecardBuilder` for formal CIS compliance reporting.
- Computes per-control-family pass/fail/warn scores, overall rule-level percentage, and trend over time using `IAuditHistoryStore`.
- Thresholds: Pass ≥90%, Warn ≥80%, Fail <80%. Named constants (`PassThreshold`, `WarnThreshold`) on `ComplianceScorecard` prevent magic-number drift.
- `NotApplicable` rules are excluded from scoring; `Suppressed` rules are excluded from the applicable denominator.
- Multi-family rules count once per family for family scores, but overall score is computed at the rule level to avoid double-counting.
- Trend capped at the last 10 audit history entries to prevent unbounded growth.
- Evidence exports include `compliance-scorecard.html` and `compliance-scorecard.md` in the signed ZIP bundle.
- Avalonia UI has a new **Compliance** tab with overall score badge, family DataGrid, and mini bar-chart trend visualization.
- 42+ unit tests covering builder logic, `CisFamilyResolver`, formatters, ViewModel, and `ComplianceTrendAnalyzer`.
  - Code: `VulcansTrace.Linux.Core/Compliance/`, `VulcansTrace.Linux.Agent/Reports/ComplianceScorecardBuilder.cs`, `VulcansTrace.Linux.Evidence/Formatters/ComplianceScorecardHtmlFormatter.cs`, `VulcansTrace.Linux.Evidence/Formatters/ComplianceScorecardMarkdownFormatter.cs`, `VulcansTrace.Linux.Avalonia/Views/ComplianceScorecardView.axaml`, `VulcansTrace.Linux.Avalonia/ViewModels/ComplianceScorecardViewModel.cs`, `VulcansTrace.Linux.Tests/Agent/ComplianceScorecardBuilderTests.cs`, `VulcansTrace.Linux.Tests/Avalonia/ComplianceScorecardViewModelTests.cs`, `VulcansTrace.Linux.Tests/Evidence/ComplianceScorecardFormatterTests.cs`

### Risk Scorecard
- Added `RiskScorecardBuilder` implementing `IRiskScorecardBuilder` for aggregate risk scoring.
- Computes numeric score (0–100), letter grade (A–F), summary status, and per-category breakdown from agent findings.
- Scoring formula: deduction per finding = `SeverityValue × 5 × AverageControlWeight`. Control weight is the average of `CisBenchmarkMapping.ControlWeight` values for the finding's CIS mappings (default 1.0).
- Defense-in-depth guards: `ControlWeight` values that are ≤0, NaN, Infinity, or >1000.0 fall back to 1.0 to prevent silent scoring bypasses and numeric overflow.
- Grade is computed from the raw score before rounding; display uses `Math.Round(..., 1, MidpointRounding.AwayFromZero)`.
- Summary status mapping: A→Low, B→Moderate, C→Elevated, D→High, F→Severe (monotonic severity progression).
- Only risk-relevant findings contribute; Info findings (severity = 0) are excluded from both the score and `TotalFindings`.
- `AgentIntent.RiskScore` and `QueryParser` keywords (`risk score`, `risk grade`, `what's my risk`, `how risky`, `risk assessment`, `overall risk`) let users ask for their risk grade in chat.
- `SecurityAgent` computes the scorecard automatically during audits via injected `IRiskScorecardBuilder` (defaults to `new RiskScorecardBuilder()` when not supplied).
- `AgentReportGenerator` forwards `RiskScorecard` from `AgentResult` to `AnalysisResult`.
- Evidence exports include `risk-scorecard.html` and `risk-scorecard.md` in the signed ZIP bundle.
- Avalonia UI has a new **Risk Score** tab with color-coded grade badge, numeric score, summary status, and per-category DataGrid.
- 25+ unit tests covering builder logic, grade boundaries, control-weight guards (zero, negative, max value), raw-score grading, category ordering, and ViewModel behavior.
  - Code: `VulcansTrace.Linux.Core/RiskScorecard.cs`, `VulcansTrace.Linux.Core/CategoryRisk.cs`, `VulcansTrace.Linux.Agent/Reports/RiskScorecardBuilder.cs`, `VulcansTrace.Linux.Agent/Reports/IRiskScorecardBuilder.cs`, `VulcansTrace.Linux.Evidence/Formatters/RiskScorecardHtmlFormatter.cs`, `VulcansTrace.Linux.Evidence/Formatters/RiskScorecardMarkdownFormatter.cs`, `VulcansTrace.Linux.Avalonia/ViewModels/RiskScorecardViewModel.cs`, `VulcansTrace.Linux.Tests/Agent/RiskScorecardBuilderTests.cs`, `VulcansTrace.Linux.Tests/Avalonia/RiskScorecardViewModelTests.cs`

## 2) Profiles and Their Capabilities

Profiles are defined in:
`VulcansTrace.Linux.Engine/Configuration/AnalysisProfileProvider.cs`

Profiles do not use the same detector set. The differences are:
- Which detectors are enabled.
- How aggressive the thresholds are.
- The minimum severity displayed in results.

### Detectors (What They Find)
- PortScan: many distinct destination ports from a single source in a window.
- Flood (DoS): very high event rates from a single source.
- LateralMovement: same source touching multiple internal hosts.
- Beaconing: periodic, low-variance intervals between communications.
- PolicyViolation: disallowed outbound ports or policy rule hits.
- Novelty: rare host/port combinations within the analyzed log.
- FlagAnomaly: suspicious TCP flag patterns (only when flags are present).
- MacSpoofing: same IP associated with multiple MAC addresses within a window.
- KernelModule: posture assessment via firewall module signature scanning (conntrack, rate limiting, Layer 7, quota/hashlimit, IPv6).
- InterfaceHopping: rapid interface changes tied to traffic patterns.
- UnusualPacketSize: anomalous packet size distributions.
- C2Detection: repeatable timing patterns suggestive of C2 channels.
- PrivilegeEscalationDetection: spikes/sweeps against admin ports.

### Severity visibility (filtering)
- Low: only shows Severity.High and above.
- Medium: shows Severity.Medium and above.
- High: shows all severities (Severity.Info and above).

### Profile characteristics and thresholds

LOW (Conservative)
- Enabled detectors:
  - PortScan, Flood, LateralMovement, Beaconing, PolicyViolation
  - FlagAnomaly, MacSpoofing
- Disabled detectors:
  - Novelty, KernelModule, InterfaceHopping, UnusualPacketSize, C2Detection,
    PrivilegeEscalationDetection
- Thresholds:
  - PortScanMinPorts = 30 (5 min window)
  - FloodMinEvents = 400 (60 sec window)
  - LateralMinHosts = 6 (10 min window)
  - BeaconMinEvents = 8, BeaconStdDevThreshold = 3.0,
    BeaconMinIntervalSeconds = 60, BeaconMaxIntervalSeconds = 900
- C2 thresholds are defined but C2 detection is disabled in Low.
  - C2ToleranceSeconds = 10.0, C2MinIntervalSeconds = 120,
    C2MaxIntervalSeconds = 3600, C2MinOccurrences = 5,
    C2MinPatternEvents = 10, C2MinGroupSize = 4
- Privilege escalation: spike window = 10 minutes, min attempts = 8, sweep min distinct = 4 (detector disabled).
  - InterfaceHoppingWindowMinutes = 10
  - MacSpoofingWindowMinutes = 10
  - PacketSizeLargeThreshold = 4000, PacketSizeSmallThreshold = 20,
    PacketSizeMinForAnalysis = 15, PacketSizeConsistencyPercent = 80,
    PacketSizeMinConsistentCount = 15, PacketSizeVarianceRatio = 0.6,
    PacketSizeMinAvgForVariance = 150
- AdminPorts = [445, 3389, 22]
- DisallowedOutboundPorts = [21, 23, 445]
- MaxFindingsPerDetector = 100
- MinSeverityToShow = High

MEDIUM (Balanced)
- Enabled detectors:
  - PortScan, Flood, LateralMovement, Beaconing, PolicyViolation, Novelty
  - FlagAnomaly, MacSpoofing, KernelModule, InterfaceHopping,
    UnusualPacketSize, C2Detection, PrivilegeEscalationDetection
- Thresholds:
  - PortScanMinPorts = 15 (5 min window)
  - FloodMinEvents = 200 (60 sec window)
  - LateralMinHosts = 4 (10 min window)
  - BeaconMinEvents = 6, BeaconStdDevThreshold = 5.0,
    BeaconMinIntervalSeconds = 30, BeaconMaxIntervalSeconds = 900
  - C2ToleranceSeconds = 5.0, C2MinIntervalSeconds = 60,
    C2MaxIntervalSeconds = 1800, C2MinOccurrences = 3,
    C2MinPatternEvents = 6, C2MinGroupSize = 3
  - PrivilegeSpikeWindowMinutes = 5, PrivilegeSpikeMinAttempts = 5,
    PrivilegeSweepMinDistinctPorts = 3
  - InterfaceHoppingWindowMinutes = 5
  - MacSpoofingWindowMinutes = 5
  - PacketSizeLargeThreshold = 3000, PacketSizeSmallThreshold = 40,
    PacketSizeMinForAnalysis = 10, PacketSizeConsistencyPercent = 70,
    PacketSizeMinConsistentCount = 10, PacketSizeVarianceRatio = 0.5,
    PacketSizeMinAvgForVariance = 100
- AdminPorts = [445, 3389, 22]
- DisallowedOutboundPorts = [21, 23, 445]
- MaxFindingsPerDetector = 100
- MinSeverityToShow = Medium

HIGH (Aggressive)
- Enabled detectors:
  - All detectors enabled (same set as Medium, with more aggressive thresholds)
- Thresholds:
  - PortScanMinPorts = 8 (5 min window)
  - FloodMinEvents = 100 (60 sec window)
  - LateralMinHosts = 3 (10 min window)
  - BeaconMinEvents = 4, BeaconStdDevThreshold = 8.0,
    BeaconMinIntervalSeconds = 10, BeaconMaxIntervalSeconds = 900
  - C2ToleranceSeconds = 8.0, C2MinIntervalSeconds = 30,
    C2MaxIntervalSeconds = 1800, C2MinOccurrences = 2,
    C2MinPatternEvents = 4, C2MinGroupSize = 3
  - PrivilegeSpikeWindowMinutes = 10, PrivilegeSpikeMinAttempts = 4,
    PrivilegeSweepMinDistinctPorts = 2
  - InterfaceHoppingWindowMinutes = 10
  - MacSpoofingWindowMinutes = 10
  - PacketSizeLargeThreshold = 2000, PacketSizeSmallThreshold = 60,
    PacketSizeMinForAnalysis = 5, PacketSizeConsistencyPercent = 60,
    PacketSizeMinConsistentCount = 5, PacketSizeVarianceRatio = 0.4,
    PacketSizeMinAvgForVariance = 80
- AdminPorts = [445, 3389, 22]
- DisallowedOutboundPorts = [21, 23, 445]
- MaxFindingsPerDetector = 100
- MinSeverityToShow = Info

## 3) Notes on Findings Behavior

- Low is intentionally quiet: the detector thresholds are high, and findings
  below Severity.High are filtered out. This is by design for conservative triage.
- Medium is the general-purpose setting for daily analysis.
- High is best for threat-hunting and forensic review where false positives are
  acceptable in exchange for coverage.
- FlagAnomaly ignores missing flags to avoid false positives from incomplete
  log lines.

## 4) Quick Capability Mapping (Logs in the Chatbox)

For iptables/nftables logs pasted into the app, the profiles can find:

LOW
- Correlated port scans that are escalated to Critical; standalone PortScan
  findings are Medium severity and hidden by Low's visibility filter
- Extreme floods (very high event bursts)
- Broad lateral movement (many internal hosts)
- High-confidence beaconing
- Policy violations on disallowed outbound ports
- Flag anomalies (only when flags are present)
- MAC spoofing

MEDIUM
- All Low findings, plus:
- Moderate port scans, floods, and lateral movement
- Novelty detection for new hosts/ports
- Kernel module and interface hopping anomalies (when present in logs)
- Unusual packet sizes
- C2 channels with moderate regularity
- Privilege escalation spikes/sweeps on admin ports

HIGH
- All Medium findings, plus:
- Lower-threshold port scans, floods, lateral movement, and beaconing
- More sensitive C2 detection
- Lower-threshold privilege escalation detection (same 10-minute window as Low, but fewer attempts required)
- Visibility for all severities (Info and above)
