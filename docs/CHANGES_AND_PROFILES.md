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

### Security Agent — CIS Benchmark Mapping
- All 32 agent rules now carry dual-layer CIS compliance mappings:
  - **CIS Controls v8** (organizational): e.g., `CIS 4.5`, `CIS 5.4`, `CIS 6.3`
  - **CIS Ubuntu 24.04 LTS Benchmark** (technical): e.g., `5.2.7 Ensure SSH root login is disabled`
  - `CisBenchmarkMapping` record extended with optional `BenchmarkReference` field
  - Mappings flow through full audits, single-rule explanations, crashes, and policy-disabled results
  - Evidence exports preserve mappings in CSV, HTML, Markdown, JSON, and STIX formats
  - HTML and Markdown compliance-context deduplication changed from `ControlId`-only grouping to `Distinct()` so unique rationale per rule is preserved
  - Code: `VulcansTrace.Linux.Core/CisBenchmarkMapping.cs`, `VulcansTrace.Linux.Agent/Rules/SecurityRules/*.cs`, `VulcansTrace.Linux.Evidence/Formatters/*.cs`

### Documentation
- Portfolio and technical docs aligned to actual behavior and formats.
  - Docs: `README.md`, `docs/portfolio/` (15 implementation portfolios),
    `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, `docs/USAGE.md`,
    `docs/DEVELOPMENT.md`, `docs/HMAC_EVIDENCE.md`, `docs/SECURITY_AGENT.md`

### Tooling
- CLI test runner supports `--intensity`, `--all`, `--export`.
  - Tool: `tools/TestAnalysis/Program.cs`

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
