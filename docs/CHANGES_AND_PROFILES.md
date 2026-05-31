# VulcansTrace Linux Edition - Change Summary and Profile Capabilities

This document summarizes the changes added in this branch and describes the
current analysis profiles (Low, Medium, High), including the detectors they
enable and the thresholds they use. It is intended as a concise portfolio
reference and a technical verification checklist.

Last updated: 2026-05-30

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
- Evidence bundle validation added to the CLI utility.
  - Code: `tools/TestAnalysis/Program.cs`

### UI and UX
- Timeline visualization: normalized placement, severity-based colors,
  time-range label, and tooltip detail.
  - Code: `VulcansTrace.Linux.Avalonia/ViewModels/TimelineViewModel.cs`
  - Code: `VulcansTrace.Linux.Avalonia/MainWindow.axaml`
  - Code: `VulcansTrace.Linux.Avalonia/MainWindow.axaml.cs`
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

### Security Agent — Interactive Remediation
- Added `AgentIntent.FixFinding` and `HandleFixFindingAsync` for guided, step-by-step remediation of a single finding.
- `QueryParser` recognizes `fix FW-001`, `remediate PORT-002`, and `resolve SSH-003` with collision-safe keyword scoring (`fix ` requires a trailing space so `what should i fix` still routes to `PrioritizeRemediation`).
- `HandleFixFindingAsync` builds a single-section `RemediationPlan`, runs `RemediationPlanValidator` to block risky commands without rollback guidance, and returns an interactive remediation card.
- UI renders preconditions, backup commands, apply commands, rollback commands, and verification commands with the same safety and structural badges used for verification commands.
- Added 10 new tests covering intent parsing, target reference extraction, and all `HandleFixFindingAsync` code paths (no context, no reference, unknown reference, success, validation failure).
- Code: `VulcansTrace.Linux.Agent/Query/AgentIntent.cs`, `VulcansTrace.Linux.Agent/Query/QueryParser.cs`, `VulcansTrace.Linux.Agent/SecurityAgent.cs`, `VulcansTrace.Linux.Avalonia/ViewModels/AgentViewModel.cs`, `VulcansTrace.Linux.Avalonia/AgentView.axaml`, `VulcansTrace.Linux.Tests/Agent/QueryParserTests.cs`, `VulcansTrace.Linux.Tests/Agent/SecurityAgentTests.cs`

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
- Added `UserAccountScanner` that reads `/etc/passwd`, `/etc/shadow`, `/etc/login.defs`, and PAM password-stack configs (`common-password`, `system-auth`, `password-auth`, plus `/etc/security/pwquality.conf`). Note: only local files are scanned; LDAP/NIS/AD users are not covered.
- Added `UserAccount`, `ShadowEntry`, `LoginDefs`, and `PamConfig` records to `ScanData`.
- Added 7 user account rules (`USER-001` through `USER-007`) with dual-layer CIS compliance mappings:
  - `USER-001` — Only root should have UID 0 (CIS 6.2)
  - `USER-002` — Empty or unset password hashes flagged; locked interactive accounts flagged at lower severity (CIS 5.4)
  - `USER-003` — Password aging enforces `PASS_MAX_DAYS <= 90`, `PASS_MIN_DAYS >= 1`, `PASS_WARN_AGE >= 7`, plus per-user shadow checks (CIS 5.4)
  - `USER-004` — PAM password-stack must include a complexity module (`pam_pwquality.so`, `pam_cracklib.so`, or `pam_passwdqc.so`) (CIS 5.4)
  - `USER-005` — Inactive or locked interactive accounts (UID >= 1000) with expired expiry dates flagged (CIS 6.2)
  - `USER-006` — Each UID should be unique (CIS 6.2)
  - `USER-007` — Regular interactive accounts should have an existing home directory (CIS 6.2)
- `EmptyPasswordRule` returns `NotApplicable` when `/etc/shadow` is unreadable (non-root), matching `KERN-006` behavior.
- `PamPasswordComplexityRule` only inspects PAM lines in the `password` management stack.
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

### Security Agent — CIS Benchmark Mapping
- All 51 agent rules now carry dual-layer CIS compliance mappings:
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
  - Exit codes: 0 (success), 1 (error), 2 (success with critical findings).
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

### Documentation
- Portfolio and technical docs aligned to actual behavior and formats.
  - Docs: `README.md`, `docs/portfolio/` (15 implementation portfolios),
    `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, `docs/USAGE.md`,
    `docs/DEVELOPMENT.md`, `docs/HMAC_EVIDENCE.md`, `docs/SECURITY_AGENT.md`

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
