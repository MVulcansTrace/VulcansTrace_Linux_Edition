# VulcansTrace Linux Edition

[![CI](https://github.com/MVulcansTrace/VulcansTrace_Linux_Edition/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/MVulcansTrace/VulcansTrace_Linux_Edition/actions/workflows/ci.yml?query=branch%3Amain)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
![.NET 9.0](https://img.shields.io/badge/.NET-9.0-512BD4?logo=dotnet&logoColor=white)
![Avalonia 11.3.17](https://img.shields.io/badge/Avalonia-11.3.17-8B44AC)
![Platform: Linux](https://img.shields.io/badge/Platform-Linux-FCC624?logo=linux&logoColor=black)
![Tests: 2380 passing](https://img.shields.io/badge/Tests-2380%20passing-2E7D32)
![Offline: 100% local](https://img.shields.io/badge/Offline-100%25%20local-2E7D32)
![Evidence: HMAC-SHA256](https://img.shields.io/badge/Evidence-HMAC--SHA256-0B7285)

VulcansTrace Linux Edition is an offline desktop forensic analyzer for Linux firewall logs. It parses iptables and nftables log text, normalizes it into a shared event schema, runs layered threat detectors, correlates related findings, and exports signed evidence bundles for investigation and handoff.

OFFLINE POLICY: the application does not send logs, telemetry, analytics, or findings anywhere. Logs are processed locally in memory, and evidence bundles are written only to user-selected files.

## Demo Preview

![VulcansTrace Linux Edition desktop analyzer preview](VulcansTrace-gif.gif)

## Contents

- [Demo Preview](#demo-preview)
- [What It Does](#what-it-does)
- [Detection Coverage](#detection-coverage)
- [Quick Start](#quick-start)
- [Evidence Bundles](#evidence-bundles)
- [Project Layout](#project-layout)
- [Documentation Guide](#documentation-guide)
- [Portfolio Deep Dives](#portfolio-deep-dives)
- [Development](#development)
- [Security Notes](#security-notes)
- [License](#license)

## What It Does

VulcansTrace is built for local investigation of Linux firewall telemetry:

- Accepts iptables kernel logs and nftables `nf_tables:` entries.
- Handles mixed-format log input by classifying lines individually.
- Converts raw log lines into `UnifiedEvent` records with shared fields and Linux-specific metadata.
- Runs baseline, Linux-specific, and advanced threat detectors.
- Escalates severity when correlated behavior appears on the same source host.
- Preserves parse errors, skipped lines, warnings, and detector output for analyst review.
- Exports reports in CSV, JSON, STIX 2.1, HTML, Markdown, and signed manifest formats — every export includes MITRE ATT&CK technique mappings for findings and rules.
- Provides a local Security Agent that answers plain-English posture questions using live host scanners, deterministic rules, role-aware local policy, dual-layer CIS Benchmark mapping (CIS Controls v8 + CIS Ubuntu 24.04 LTS technical controls), and **MITRE ATT&CK technique mapping** for audit-ready compliance traceability — including interactive, step-by-step guided remediation for individual findings with safety-classified commands, a compact impact preview showing expected change, rollback path, and verification command before every apply step, rollback visibility, session notes with evidence links, and batch auto-fix with dry-run preview for headless remediation.
- File Permission Auditing — checks `/etc/shadow`, `/etc/passwd`, SSH host private keys, user and root SSH directories, cron directories, and `/etc/crontab` for overly permissive permissions or incorrect ownership.
- Filesystem Auditing — hunts broadly for world-writable files outside expected paths, unexpected SUID/SGID binaries, unowned files, world-writable directories without sticky bit, and `/tmp` mount hardening (`noexec`, `nosuid`, `nodev`).
- User & Account Auditing — checks UID 0 beyond root, empty password hashes, password aging from `/etc/login.defs` and shadow entries, PAM password complexity, inactive accounts, duplicate UIDs, missing home directories, PAM faillock / account lockout configuration, detailed password quality requirements (`minlen`, `minclass`, credits), and PAM auth stack ordering (`required` before `sufficient`).
- Cron Job Auditing — checks cron entries for suspicious commands (reverse shells, network downloaders, temp paths), world-writable or setuid/setgid cron scripts, and root jobs referencing non-root user directories.
- Container Security Auditing — checks running containers for privileged mode, `latest` image tags, Docker socket exposure/mounts, known risky base-image hints, and containerd namespace isolation.
- Kubernetes Security Auditing — checks Kubernetes pod security posture for privileged containers, hostNetwork/hostPID/hostIPC sharing, root containers, and missing security contexts (privilege escalation, readOnlyRootFilesystem, dropped capabilities, confined seccomp).
- Configuration Baseline & Drift Detection — snapshot a "known good" baseline and continuously monitor for drift.
- **Recurring Audit Scheduling** — configure automatic recurring audits (daily, weekly, etc.) via standard Linux `cron`. Notifications are sent only when **new** critical findings appear, using fingerprint-aware diffing against previous audit history.
- **Headless CLI** — run audits and manage schedules from the command line without launching the desktop UI.
- **CIS Compliance Scorecard** — formal pass/fail/warn per control family, overall percentage score, and trend over time, readable in 10 seconds by managers and auditors. Included in the Avalonia UI and evidence exports.
- **Risk Scorecard** — aggregate letter grade (A–F) and numeric score (0–100) derived from all risk-relevant findings, weighted by severity and CIS control importance. Surfaces top risk categories by deduction and is included in the Avalonia UI, agent chat, and evidence exports.
- **Trace Map / Incident Graph** — interactive attack-chain visualization on the timeline canvas. Correlated findings are connected with directed edges (escalation, temporal sequence, same-host links). Click any finding to highlight its connected chain and read a narrative attack story. Supports category-based or host-based grouping. Performance guardrails suppress rendering when >100 edges are detected.
- **Automated Incident Response Playbooks** — when `TraceMapCorrelator` detects a critical attack chain (Beaconing → LateralMovement → PrivilegeEscalation on the same host), the system auto-generates active countermeasures: `iptables`/`ip6tables` DROP rules to block the attacker's C2 IP and tagged `auditd` connect telemetry for analyst correlation. Countermeasures run through a dry-run preview first, then require explicit analyst confirmation before live deployment. Invalid attacker IPs are rejected, duplicates are deduplicated, and verification uses exact-rule matching.
- **Multi-channel Notifications** — Desktop (`notify-send`), Email (SMTP), and Webhook (HTTP POST) channels for critical-finding alerts.
- **Log Diff Mode** — compare two firewall log files (baseline vs incident) to detect new, removed, or changed connection patterns and findings. Events are matched by a traffic pattern key (source IP, destination IP, destination port, protocol; source port wildcarded) with count deltas and dominant action shifts. Findings are matched by stable fingerprint. Produces a narrative summary, per-pattern diff state (`Unchanged`, `Added`, `Removed`, `Changed`), and color-coded DataGrid visualization in the Avalonia UI. CLI diff results can be exported as JSON/HTML or included in signed evidence bundles with Markdown and HTML reports.
- **Live Stream / Real-Time Kernel Telemetry** — captures live network events from the kernel via `AF_PACKET` with classic BPF socket filtering or `AF_NETLINK` NFLOG, buffers them in a rolling window, and runs the detector pipeline in real time using a dedicated `SentryAnalyzer` instance. Completed analysis results are published through a bounded `DropOldest` channel so the UI never stalls on stale updates. Includes a synthetic demo source for zero-privilege testing. Desktop UI shows live metrics and delta findings as they are detected; findings are wired into the shared findings grid.

The desktop app is implemented with Avalonia and targets .NET 9.0.

## Detection Coverage

Baseline network detectors:

- Port scan detection
- Flood / denial-of-service burst detection
- Lateral movement detection
- Beaconing detection
- Policy violation detection
- Novelty detection

Linux deep-inspection detectors:

- TCP flag anomaly detection
- MAC spoofing detection
- Kernel module / firewall capability indicators
- Interface hopping detection
- Unusual packet size detection

Advanced detectors and correlation:

- C2 channel detection
- Privilege escalation indicators from suspicious admin-port access
- Risk escalation for correlated findings such as Beaconing + LateralMovement, FlagAnomaly + PortScan, and MacSpoofing + InterfaceHopping
- Trace Map correlation engine discovers directed attack chains across findings based on host grouping, time proximity, and known kill-chain pairs

## Quick Start

Prerequisites:

- .NET 9.0 SDK
- Linux desktop environment for running the Avalonia UI

Build the solution:

```bash
dotnet build
```

Run the desktop app:

```bash
dotnet run --project VulcansTrace.Linux.Avalonia
```

Run the test suite:

```bash
dotnet test
```

Run the optional CLI analysis tool against a sample log:

```bash
dotnet run --project tools/TestAnalysis -- VulcansTrace.Linux.Tests/Data/Real/Samples/iptables-attack.log
```

Run performance tooling:

```bash
dotnet run --project VulcansTrace.Linux.PerformanceConsole
dotnet run --project VulcansTrace.Linux.PerformanceConsole -- profile
```

Run a headless audit via CLI:

```bash
dotnet run --project VulcansTrace.Linux.Cli -- audit --intent FullAudit --role Server
```

Export a MITRE ATT&CK Navigator layer for visual coverage analysis:

```bash
dotnet run --project VulcansTrace.Linux.Cli -- audit --intent FullAudit --role Server --output-mitre mitre-layer.json
```

Preview and apply automatic remediation after an audit:

```bash
# Dry-run: see what would change without executing
dotnet run --project VulcansTrace.Linux.Cli -- audit --intent FullAudit --auto-fix --dry-run

# Apply safe fixes with confirmation
dotnet run --project VulcansTrace.Linux.Cli -- audit --intent FullAudit --auto-fix --yes

# Also permit service restarts and package operations
dotnet run --project VulcansTrace.Linux.Cli -- audit --intent FullAudit --auto-fix --yes --allow-restart --allow-packages
```

Manage recurring schedules via CLI:

```bash
dotnet run --project VulcansTrace.Linux.Cli -- schedule list
dotnet run --project VulcansTrace.Linux.Cli -- schedule add --name "Daily Full Audit" --intent FullAudit --cron "0 6 * * *" --role Server --notify-on-critical --channel Desktop
```

Build a self-contained CLI binary:

```bash
./scripts/publish-cli.sh
```

Compare two firewall logs via CLI to detect deltas:

```bash
dotnet run --project VulcansTrace.Linux.Cli -- diff --baseline baseline.log --incident incident.log --intensity Medium --output-evidence diff-evidence.zip
```

Start a live stream capture in the desktop UI (requires root for kernel sources; synthetic demo works without privileges):

```bash
dotnet run --project VulcansTrace.Linux.Avalonia
# Select the "Live Stream" tab, choose a source (Synthetic Demo, Packet Capture, or NFLOG), and click Start.
```

For a guided product walkthrough, see [docs/DEMO.md](docs/DEMO.md).
For live stream architecture and bug-fix details, see [docs/LIVE_STREAM.md](docs/LIVE_STREAM.md).

## Evidence Bundles

Signed ZIP evidence packages can contain:

| File | Purpose |
| --- | --- |
| `findings.csv` | Spreadsheet-friendly finding list |
| `findings.json` | Structured JSON output for tooling and review |
| `findings.stix.json` | STIX 2.1 bundle with observed data and notes |
| `report.html` | Human-readable HTML report |
| `summary.md` | Markdown investigation summary |
| `log.txt` | Original raw log text |
| `suppressions.csv` | Active accepted-risk suppressions, when present |
| `manifest.json` | File hashes, parse metadata, skipped lines, and bundle metadata |
| `manifest.hmac` | HMAC-SHA256 signature over the manifest |
| `compliance-scorecard.html` | Manager-friendly HTML compliance scorecard (Pass/Warn/Fail per CIS family, overall score, trend) |
| `compliance-scorecard.md` | Markdown compliance scorecard for Git-based workflows |
| `risk-scorecard.html` | Manager-friendly HTML risk scorecard (grade badge, numeric score, per-category breakdown) |
| `risk-scorecard.md` | Markdown risk scorecard for Git-based workflows |
| `incident-story.md` | Flowing incident narrative with timeline beats, likely chain summary, and recommended response when findings are present |
| `trace-map.md` | Technical edge-list Markdown when correlated findings are detected |
| `trace-map.json` | Cytoscape.js-compatible JSON graph of findings and correlation edges |
| `mitre-navigator-layer.json` | MITRE ATT&CK Navigator layer (JSON) showing technique coverage and finding density |
| `log-diff.md` | Markdown diff report when Log Diff Mode is used (baseline vs incident comparison) |
| `log-diff.html` | Dark-themed HTML diff report when Log Diff Mode is used |

The signing key is generated per completed analysis session and shown in the UI masked by default. Re-running analysis creates a new key; repeated exports of the same result reuse the session key. Keep the copied key with the case record if later verification is required.

For CLI `diff --output-evidence`, provide `--signing-key <hex>` or save the generated key printed by the command.

The optional CLI runner can verify an exported bundle with that key:

```bash
dotnet run --project tools/TestAnalysis -- --verify evidence.zip --key <64-character-hex-key>
```

Evidence documentation:

- [HMAC evidence signing key flow](docs/HMAC_EVIDENCE.md)
- [Evidence packaging portfolio](docs/portfolio/09-Evidence-Packaging/README.md)
- [Security and offline policy](docs/SECURITY.md)

## Project Layout

| Path | Description |
| --- | --- |
| `VulcansTrace.Linux.Core` | Domain models, `UnifiedEvent`, log normalization, iptables/nftables parsers, and logging abstractions |
| `VulcansTrace.Linux.Engine` | Detector implementations, intensity profiles, `SentryAnalyzer`, and risk escalation |
| `VulcansTrace.Linux.Evidence` | Evidence bundle generation and CSV, JSON, STIX, HTML, and Markdown formatters |
| `VulcansTrace.Linux.Agent` | Local Security Agent, scanners, posture rules, role-aware policy, explanations, and agent report adapter |
| `VulcansTrace.Linux.Avalonia` | Desktop UI, ViewModels, commands, and dialog services |
| `VulcansTrace.Linux.Cli` | Headless CLI for audits, schedule management, and cron integration |
| `VulcansTrace.Linux.Tests` | xUnit unit, integration, detector, evidence, UI, and performance tests |
| `VulcansTrace.Linux.Performance` | Benchmark and profiling helpers |
| `VulcansTrace.Linux.PerformanceConsole` | Console runner for benchmark and profiling workflows |
| `tools/TestAnalysis` | Optional CLI runner for direct log-file analysis and evidence export checks |
| `docs` | Architecture, usage, security, development, demo, and portfolio documentation |
| `scripts` | Developer and internal build-support scripts |

## Documentation Guide

Start here depending on what you need:

| Document | Use It For |
| --- | --- |
| [docs/USAGE.md](docs/USAGE.md) | How to run the app, analyze logs, review findings, and export evidence |
| [docs/DEMO.md](docs/DEMO.md) | A guided walkthrough using sample firewall logs |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System layers, data flow, detector groups, and domain types |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | Build/test workflow, project layout, detector extension steps, and build policies |
| [docs/SECURITY.md](docs/SECURITY.md) | Offline policy, local data handling, evidence integrity, and defensive parsing |
| [docs/SECURITY_AGENT.md](docs/SECURITY_AGENT.md) | Local Security Agent capabilities, scanner pipeline, rules, limitations, and roadmap |
| [docs/HMAC_EVIDENCE.md](docs/HMAC_EVIDENCE.md) | How session signing keys are generated, copied, and used for verification |
| [docs/CHANGES_AND_PROFILES.md](docs/CHANGES_AND_PROFILES.md) | Implementation change summary and Low/Medium/High profile capabilities |
| [docs/LIVE_STREAM.md](docs/LIVE_STREAM.md) | Real-time kernel telemetry: architecture, sources, bug fixes, and hardening |
| [docs/portfolio/README.md](docs/portfolio/README.md) | GitHub-facing index for the complete technical portfolio |

Recommended review paths:

- For usage: [Usage](docs/USAGE.md) -> [Demo](docs/DEMO.md) -> [Evidence signing](docs/HMAC_EVIDENCE.md)
- For architecture: [Architecture](docs/ARCHITECTURE.md) -> [Log Normalization](docs/portfolio/01-Log-Normalization/README.md) -> [Intensity Profiles](docs/portfolio/10-Intensity-Profiles/README.md)
- For detection engineering: [Port Scan Detection](docs/portfolio/02-Port-Scan-Detection/README.md) -> [Beaconing Detection](docs/portfolio/03-Beaconing-Detection/README.md) -> [C2 Channel Detection](docs/portfolio/13-C2-Channel-Detection/README.md)
- For threat-framework coverage: [Evidence Packaging](docs/portfolio/09-Evidence-Packaging/README.md) -> [Security Agent](docs/portfolio/16-Security-Agent/README.md) -> [Automated Tests](docs/portfolio/11-Automated-Tests/README.md)
- For investigation workflow: [Risk Escalation](docs/portfolio/08-Risk-Escalation/README.md) -> [Evidence Packaging](docs/portfolio/09-Evidence-Packaging/README.md) -> [Avalonia UI](docs/portfolio/12-Avalonia-UI/README.md)
- For local assistant workflow: [Security Agent](docs/SECURITY_AGENT.md) -> [Security Agent portfolio](docs/portfolio/16-Security-Agent/README.md) -> [Avalonia UI](docs/portfolio/12-Avalonia-UI/README.md)
- For scheduling and automation: [Usage](docs/USAGE.md) -> [Changes](docs/CHANGES_AND_PROFILES.md) -> [Security](docs/SECURITY.md)
- For live kernel telemetry: [Live Stream](docs/LIVE_STREAM.md) -> [Live Stream Portfolio](docs/portfolio/17-Live-Stream/README.md) -> [Architecture](docs/ARCHITECTURE.md)
- For verification: [Automated Tests](docs/portfolio/11-Automated-Tests/README.md) -> [Development](docs/DEVELOPMENT.md) -> [Security](docs/SECURITY.md)

## Portfolio Deep Dives

The `docs/portfolio` folder contains 16 implementation-focused case studies. Each topic includes a `README.md`, concise summary material, and deeper technical notes such as algorithms, design decisions, evasion limits, MITRE ATT&CK mapping where relevant, and code-pattern walkthroughs.

| Topic | Description |
| --- | --- |
| [01 - Log Normalization](docs/portfolio/01-Log-Normalization/README.md) | iptables/nftables parsing, timestamp handling, schema normalization, and log-management tradeoffs |
| [02 - Port Scan Detection](docs/portfolio/02-Port-Scan-Detection/README.md) | Distinct-port scan detection, thresholds, grouping, and detector behavior |
| [03 - Beaconing Detection](docs/portfolio/03-Beaconing-Detection/README.md) | Periodic communication analysis and interval-based signal detection |
| [04 - Lateral Movement Detection](docs/portfolio/04-Lateral-Movement-Detection/README.md) | Internal movement patterns across hosts and ports |
| [05 - Flood Detection](docs/portfolio/05-Flood-Detection/README.md) | High-volume burst detection for flood and DoS-style behavior |
| [06 - Policy Violation Detection](docs/portfolio/06-Policy-Violation-Detection/README.md) | Disallowed service and policy-boundary detection |
| [07 - Novelty Detection](docs/portfolio/07-Novelty-Detection/README.md) | Rare or unexpected connection pattern detection |
| [08 - Risk Escalation](docs/portfolio/08-Risk-Escalation/README.md) | Correlation rules that raise severity when related findings appear together |
| [09 - Evidence Packaging](docs/portfolio/09-Evidence-Packaging/README.md) | Signed evidence bundles, report formats, manifest hashing, and integrity workflow |
| [10 - Intensity Profiles](docs/portfolio/10-Intensity-Profiles/README.md) | Low, Medium, and High profile thresholds, detector enablement, and tuning tradeoffs |
| [11 - Automated Tests](docs/portfolio/11-Automated-Tests/README.md) | Unit, integration, fixture, cancellation, performance, and evidence-verification coverage |
| [12 - Avalonia UI](docs/portfolio/12-Avalonia-UI/README.md) | Desktop analyst workflow, ViewModel structure, commands, tabs, and export UX |
| [13 - C2 Channel Detection](docs/portfolio/13-C2-Channel-Detection/README.md) | Periodic command-and-control channel detection and grouping behavior |
| [14 - Privilege Escalation Detection](docs/portfolio/14-Privilege-Escalation-Detection/README.md) | Admin-port spikes and sweeps as privilege-escalation indicators |
| [15 - Linux Deep Inspection](docs/portfolio/15-Linux-Deep-Inspection/README.md) | Linux-specific signals including flags, MACs, kernel modules, interfaces, and packet sizes |
| [16 - Security Agent](docs/portfolio/16-Security-Agent/README.md) | Local rule-based assistant for live Linux posture questions, role-aware policy, scanner orchestration, explanations, interactive remediation, and configuration baseline / drift detection |

## Development

Common commands:

```bash
dotnet restore VulcansTrace.Linux.sln
dotnet build VulcansTrace.Linux.sln --configuration Release
dotnet test VulcansTrace.Linux.sln --configuration Release
```

GitHub Actions runs restore, Release build, and the deterministic test set (2 143 tests). Tests marked `Category=Performance` or `Category=Timing` are kept out of hosted CI because benchmark thresholds and millisecond cancellation races are runner-sensitive; run the full suite locally when validating performance changes.

To add a detector, implement `IDetector`, register it with the analyzer composition root, add focused detector tests, update profile thresholds if needed, and document the behavior in the relevant portfolio section. See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for the detailed checklist.

## Security Notes

- The app has no built-in network calls for log analysis, telemetry, or reporting.
- `nuget.config` points to the public nuget.org feed for restore.
- Log input is capped at 100,000,000 characters.
- Retained parse errors are capped to keep analysis output bounded.
- Evidence files are protected by SHA-256 hashes and an HMAC-SHA256 manifest signature.

See [docs/SECURITY.md](docs/SECURITY.md) for the full security model.

## License

This repository is licensed under the terms in [LICENSE](LICENSE). Additional attribution and notice information is available in [NOTICE](NOTICE).
