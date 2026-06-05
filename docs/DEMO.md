# VulcansTrace Linux Edition - Demo Guide

This guide walks through the key features of VulcansTrace Linux Edition.

## Launch the Application

```bash
dotnet run --project VulcansTrace.Linux.Avalonia
```

## Load Sample Firewall Log

Use one of the sample logs from the test data:

- `VulcansTrace.Linux.Tests/Data/Real/Samples/iptables-attack.log`
- Or paste sample log content directly into the text area

Sample iptables log snippet:
```
kernel: Jan 19 10:15:32 server IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=192.168.1.100 DST=192.168.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 DF PROTO=TCP SPT=54321 DPT=22 WINDOW=64240 RES=0x00 SYN
kernel: Jan 19 10:15:33 server IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=192.168.1.100 DST=192.168.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12346 DF PROTO=TCP SPT=54321 DPT=23 WINDOW=64240 RES=0x00 SYN
```

## Select Analysis Intensity

Choose from three intensity levels:

- **Low**: Critical threat triage (conservative thresholds)
- **Medium**: Investigation review (balanced thresholds)
- **High**: Deep hunt / forensics (aggressive thresholds)

## Run Analysis

Click the "Analyze" button to process the log and detect security findings.

## Review Findings

- Check the **Findings** tab for detected threats — the **MITRE ATT&CK** column shows mapped techniques for each finding
- Switch to **Timeline** to visualize events over time with time-scaled bars per category
- Toggle **Trace Map** to reveal directed correlation edges between related findings (dashed lines). Click any bar to highlight its connected attack chain — other findings dim. A narrative panel appears below the timeline describing the attack story
- Toggle **Group by Host** to re-group the timeline Y-axis by source host instead of category
- Review **Parse Errors** and **Warnings** tabs if needed
- The top panel shows total findings, high/critical alerts, warnings, parse errors, skipped lines, and advisor tips

## Export Evidence

Click **Export Evidence** to generate a signed ZIP bundle containing:

| File | Format |
|------|--------|
| `findings.csv` | CSV |
| `findings.json` | SIEM-friendly JSON |
| `findings.stix.json` | STIX 2.1 bundle (identity, observed-data, notes, IP observables) |
| `report.html` | Formatted HTML report |
| `summary.md` | Markdown summary |
| `log.txt` | Original raw log |
| `incident-story.md` | Attack-chain narrative when correlated findings are detected |
| `trace-map.json` | Cytoscape.js-compatible graph for import into network visualization tools |
| `mitre-navigator-layer.json` | MITRE ATT&CK Navigator layer v4.5 with detector/rule coverage and observed finding scoring |
| `manifest.json` + `manifest.hmac` | HMAC integrity verification |

## Sample Attack Scenarios

The sample log (`iptables-attack.log`) demonstrates a **port scan** — one source host probing 39 distinct destination ports in rapid succession. It reliably surfaces PortScan findings at Medium and High intensity. At Low intensity, the detector still evaluates the traffic, but standalone PortScan findings are emitted at Medium severity and are hidden by Low's High/Critical visibility filter unless they are escalated by correlation.

For logs that trigger other detectors, use the integration test fixtures or craft logs with:
- **TCP flags** (`FLAGS=FIN`, `FLAGS=FIN,PSH,URG`) for FlagAnomaly
- **Multiple MACs** per source IP for MacSpoofing
- **Multiple interfaces** (`IN=eth0` / `IN=eth1`) for InterfaceHopping
- **Packet lengths** (`LEN=60`, `LEN=5000`) for UnusualPacketSize
- **Periodic intervals** spanning minutes/hours for Beaconing and C2Channel
- **Multiple destination hosts** for LateralMovement
- **High-volume bursts** for Flood/DoS

## Security Agent — Kernel Hardening Audit

The Security Agent audits kernel and system hardening parameters without pasting a log:

1. Open the **Security Agent** panel in the UI.
2. Type: `Check my kernel hardening`
3. The agent runs `KernelHardeningScanner` and evaluates rules for:
   - ASLR (`kernel.randomize_va_space`)
   - IP forwarding (`net.ipv4.ip_forward`, `net.ipv6.conf.all.forwarding`)
   - ICMP redirects (`net.ipv4.conf.all.accept_redirects`)
   - Source routing (`net.ipv4.conf.all.accept_source_route`)
   - Kernel module loading restrictions (`kernel.modules_disabled`)
   - Secure Boot status
   - Kernel pointer exposure (`kernel.kptr_restrict`, `kernel.dmesg_restrict`)
4. Review findings in the chat panel and the main findings grid.
5. Ask follow-ups like `What should I fix first?` or `Explain KERN-001`.

## Security Agent — File Permission Audit

The Security Agent can audit sensitive file and directory permissions without pasting a log:

1. Open the **Security Agent** panel in the UI.
2. Type: `Check file permissions`
3. The agent runs `FilePermissionScanner` and evaluates rules for:
   - `/etc/shadow`, `/etc/passwd`
   - SSH host private keys (`/etc/ssh/ssh_host_*_key`)
   - Root and user SSH directories (`~/.ssh`, `~/.ssh/authorized_keys`)
   - Cron directories and `/etc/crontab`
4. Review findings in the chat panel and the main findings grid.
5. Ask follow-ups like `What should I fix first?` or `Explain FILE-001`.

## Security Agent — Filesystem Audit

The Security Agent can audit the broader filesystem for dangerous permission patterns without pasting a log:

1. Open the **Security Agent** panel in the UI.
2. Type: `Check my filesystem`
3. The agent runs `FilesystemAuditScanner` and evaluates rules for:
   - World-writable files outside `/tmp`, `/var/tmp`, `/dev/shm`, and other expected paths (`FSYS-001`)
   - Unexpected SUID/SGID binaries not matching the known-good full-path whitelist (`FSYS-002`)
   - Unowned files (no valid user or group) (`FSYS-003`)
   - World-writable directories without the sticky bit (`FSYS-004`)
   - `/tmp` mounted as a separate partition with `noexec`, `nosuid`, and `nodev` (`FSYS-005`)
4. Review findings in the chat panel and the main findings grid.
5. Ask follow-ups like `What should I fix first?` or `Explain FSYS-002`.

## Security Agent — User Account Audit

The Security Agent audits local user accounts, password aging, and PAM configuration without pasting a log:

1. Open the **Security Agent** panel in the UI.
2. Type: `Check my user accounts`
3. The agent runs `UserAccountScanner` and evaluates rules for:
   - UID 0 accounts beyond root
   - Empty or unset password hashes
   - Password aging from `/etc/login.defs` and per-user shadow entries
   - PAM password complexity module presence
   - Inactive or locked interactive accounts
   - Duplicate UIDs
   - Missing home directories for regular users
4. Review findings in the chat panel and the main findings grid.
5. Ask follow-ups like `What should I fix first?` or `Explain USER-001`.

## Security Agent — Cron Job Audit

The Security Agent audits scheduled cron jobs for suspicious entries, dangerous script permissions, and privilege misuse without pasting a log:

1. Open the **Security Agent** panel in the UI.
2. Type: `Check my cron jobs`
3. The agent runs `CronJobScanner` and evaluates rules for:
   - Suspicious cron commands (reverse shells, network downloaders, temp paths, encoded payloads) (`CRON-001`)
   - World-writable or setuid/setgid cron scripts (`CRON-002`)
   - Root cron jobs that reference non-root user directories (`CRON-003`)
4. Review findings in the chat panel and the main findings grid.
5. Ask follow-ups like `What should I fix first?` or `Explain CRON-001`.

## Security Agent — Container Security Audit

The Security Agent audits local container runtime state without making network calls:

1. Open the **Security Agent** panel in the UI.
2. Type: `Check my containers`
3. The agent runs `ContainerScanner` and evaluates rules for:
   - Privileged containers running on the host (`CTR-001`)
   - Container images using the `latest` tag or no explicit tag (`CTR-002`)
   - Docker socket exposed on the host or mounted into running containers (`CTR-003`)
   - Containerd using only the default namespace without explicit isolation (`CTR-004`)
   - Known risky base-image hints such as end-of-life distro bases (`CTR-005`)
4. Review findings in the chat panel and the main findings grid.
5. Ask follow-ups like `What should I fix first?` or `Explain CTR-001`.

## Security Agent — Kubernetes Security Audit

The Security Agent audits Kubernetes pod security posture via `kubectl` when a kubeconfig is present. `kubectl` uses the configured cluster context, so this may contact that cluster API:

1. Open the **Security Agent** panel in the UI.
2. Type: `Check my kubernetes` or `Check my pods`
3. The agent runs `KubernetesScanner` and evaluates rules for:
   - Pods running privileged containers (`K8S-001`)
   - Pods sharing hostNetwork, hostPID, or hostIPC namespaces (`K8S-002`)
   - Containers that may run as root (`K8S-003`)
   - Missing security context hardening (privilege escalation disabled, readOnlyRootFilesystem, dropped capabilities, confined seccomp) (`K8S-004`)
4. Review findings in the chat panel and the main findings grid.
5. Ask follow-ups like `What should I fix first?` or `Explain K8S-001`.

## Security Agent — Remediation Session History Browser

The agent persists all guided remediation sessions so you can review, resume, or delete them later:

1. Open the **Security Agent** panel in the UI.
2. Expand the **Remediation Sessions** section below the audit history.
3. The list shows every persisted session with its ID, status, rule ID, and creation time.
4. Select a session and click **Resume** to reload it into the chat panel for review or verification.
5. Click **Delete** to remove a session from the store.
6. Alternatively, type in chat:
   - `List my sessions` or `Show sessions` — lists all sessions
   - `Resume session abc12345` — loads a specific session

Sessions are persisted to `~/.config/VulcansTrace/remediation-sessions.json` when available, with an in-memory fallback.

## Security Agent — Remediation Preview And Sessions

After running any audit, you can ask the agent for either a single-finding remediation preview or a persisted guided session:

1. Run an audit: `Check my firewall`
2. When findings appear, type `Fix FW-001` for a preview, or `Remediate FW-001` to start a guided remediation session.
3. The agent returns an interactive remediation card/session with:
   - **Impact Preview** — a compact panel summarizing the expected impact, rollback path, and verification command before the detailed command lists
   - **Preconditions** — checklist items such as "Root or sudo access" and "Console access available"
   - **Backup commands** — run these first to preserve state (e.g., `iptables-save`)
   - **Apply commands** — step-by-step fix commands, each with a safety badge
   - **Rollback commands** — how to undo if something goes wrong
   - **Verification commands** — confirm the fix worked
4. Review each command before copying and running it. Safety badges classify every command as `ReadOnly`, `ConfigChange`, `ServiceRestart`, `PackageInstall`, `Destructive`, or `Unknown`, plus structural warnings (`SUDO`, `CHAIN`, `PIPE`, `REDIR`, `DL-EXEC`).
5. For sessions, click **Verify Remediation** or type `verify remediation <session-id>` after completing the manual steps. The agent re-runs the original audit intent and reports fixed, unchanged, new, and worsened findings. If verification is blocked or crashes after starting, the session timeline records that terminal outcome.
6. Use **Export Session** to save a markdown session report with step state, blocked reasons, before snapshot, remediation plan, and verification diff. The `Exported` timeline event is recorded only after the report is written successfully.
7. If the finding's explanation template lacks rollback guidance for risky commands, the plan/session is blocked for safety. Blocked sessions remain visible for auditability but do not expose copyable remediation commands or allow verification as completed remediation.

## Security Agent — Automated Incident Response Playbooks

When the Trace Map detects a critical attack chain (Beaconing → LateralMovement → PrivilegeEscalation on the same compromised host), the agent can deploy active countermeasures directly from the chat panel:

1. Paste or analyze a firewall log that triggers Beaconing, LateralMovement, and PrivilegeEscalation findings on the same source host (for example, `192.168.1.100` beaconing to `10.0.0.5:443`, then pivoting internally, then scanning admin ports).
2. The Security Agent chat panel displays a critical chain message with:
   - Compromised host (`192.168.1.100`)
   - Attacker C2 IP (`10.0.0.5`)
   - Attack stage narrative (`Beaconing → LateralMovement → PrivilegeEscalation`)
   - A **Deploy Countermeasures** button
3. Click **Deploy Countermeasures**. The system runs a dry-run preview first:
   - Parses and validates the attacker IP (`10.0.0.5`) before command generation
   - Generates `iptables -A INPUT -s 10.0.0.5 -j DROP` and tagged `auditctl -a ... -S connect -k vulcanstrace_countermeasure_10_0_0_5` telemetry
   - Shows `[DRY-RUN]` results in chat
4. If the dry-run passes, a confirmation dialog appears with two options:
   - **Deploy Live** — execute the countermeasures
   - **Cancel** — abort without changes
5. Click **Deploy Live** to execute:
   - Backup commands run first (if any)
   - Apply commands: firewall DROP + tagged auditd connect telemetry
   - Verification: `iptables -C INPUT -s 10.0.0.5 -j DROP` confirms the rule is active
6. Results are posted to chat with `[LIVE]` prefix. If any apply command fails, automatic rollback runs for that section.

**Safety notes:**
- Invalid attacker IPs (e.g., `not-an-ip:443`) produce a blocked section with a clear risk note — no commands are generated
- Multiple critical chains targeting the same attacker IP are deduplicated to a single section
- Verification uses `iptables -C` exact-rule checking, not `grep`
- All commands feed through bash stdin to prevent shell injection

## Security Agent — Auto-Fix (Batch Remediation)

The headless CLI can automatically remediate multiple findings after an audit:

1. Preview what would change without executing:
   ```bash
   vulcanstrace audit --intent FullAudit --auto-fix --dry-run
   ```
   The output shows an impact preview for each finding (expected impact, rollback path, and verification command), which commands would execute, which would be skipped by policy, and any validation warnings.

2. Apply safe fixes with confirmation:
   ```bash
   vulcanstrace audit --intent FullAudit --auto-fix --yes
   ```
   The executor runs backup commands first, then apply commands, then verification commands. If any apply command fails, rollback commands are executed automatically for that section.

3. Expand the policy for broader fixes:
   ```bash
   vulcanstrace audit --intent FullAudit --auto-fix --yes --allow-restart --allow-packages
   ```

**Safety behavior:**
- Default policy allows `ReadOnly` and `ConfigChange` commands only.
- `--allow-restart` permits service restarts; `--allow-packages` permits package operations.
- Destructive and unclassified commands are never auto-executed.
- Sections without explicit rollback guidance are skipped.
- Backup failures abort the section to prevent unsafe changes.
- Apply failures trigger automatic rollback for that section.
- Critical findings still return exit code `2` even when auto-fix succeeds.

## CIS Compliance Scorecard

After any agent audit, view the formal compliance scorecard:

1. Run an audit: `Is my system secure?`
2. Switch to the **Compliance** tab.
3. Review the overall score badge:
   - **Pass** (green) — overall score ≥90% and no failed families
   - **Warn** (yellow) — overall score ≥80% but <90%, or at least one family is Warn
   - **Fail** (red) — overall score <80%, any family failed, or any rule crashed
4. Review the **Control Families** grid for per-family totals, passed counts, failed counts, score percentage, and status.
5. Review the **Trend** bar chart showing overall scores from previous audits (up to 10 entries).
6. Export evidence — the signed ZIP includes `compliance-scorecard.html` and `compliance-scorecard.md` for manager handoff.

Scorecard rules:
- **NotApplicable** rules are excluded from scoring entirely.
- **Suppressed** rules are excluded from the applicable total.
- Multi-family rules count once per family in family scores, but the overall score is rule-level (no double-counting).

## Risk Scorecard

After any agent audit, view the aggregate risk scorecard:

1. Run an audit: `Is my system secure?`
2. Switch to the **Risk Score** tab.
3. Review the grade badge:
   - **A** (green) — score ≥90, Low risk
   - **B** (blue) — score ≥80, Moderate risk
   - **C** (yellow) — score ≥70, Elevated risk
   - **D** (orange) — score ≥60, High risk
   - **F** (red) — score <60, Severe risk
4. Review the numeric score (0–100) and summary status.
5. Review the **By Category** breakdown showing finding counts, average severity, and total deduction per category.
6. Ask in chat: `What's my risk grade?` — the agent returns the scorecard summary without switching tabs.
7. Export evidence — the signed ZIP includes `risk-scorecard.html` and `risk-scorecard.md` for manager handoff.

Scoring rules:
- Deduction per finding = `SeverityValue × 5 × AverageControlWeight`
- Control weight defaults to 1.0; zero, negative, NaN, Infinity, and excessive weights fall back to 1.0
- Info findings (severity = 0) do not contribute to the risk score
- Total score = `max(0, 100 − TotalDeduction)`
- Grade is computed from the raw score before rounding; display uses 1-decimal rounding

## Recurring Audit Scheduling — GUI

1. Open the **Schedules** tab in the Avalonia UI.
2. Click **Add** to create a schedule:
   - Name: `Daily Server Audit`
   - Intent: `FullAudit`
   - Cron: `0 6 * * *` (daily at 06:00)
   - Role: `Server`
   - Channel: `Desktop`
   - Check **Notify on critical findings**
3. Click **Save**, then select the schedule and click **Install in Cron**.
4. The schedule appears in the grid with a green checkmark under the **In Cron** column.
5. Click **Run Now** to execute the schedule immediately. Results are persisted to the audit history store.

## Recurring Audit Scheduling — CLI

```bash
# Add a daily audit schedule
vulcanstrace schedule add --name "Daily Server Audit" --intent FullAudit --cron "0 6 * * *" --role Server --notify-on-critical --channel Desktop

# List schedules
vulcanstrace schedule list

# Install the schedule into the system crontab
vulcanstrace schedule install-cron --id <schedule-id-from-list>

# Run the schedule immediately
vulcanstrace schedule run --id <schedule-id>

# Uninstall from cron when no longer needed
vulcanstrace schedule uninstall-cron --id <schedule-id>
```

Scheduled audits only notify when **new** critical findings appear, using fingerprint-aware diffing against the previous audit history.

## Headless Audit via CLI

```bash
# Run a full audit without the GUI
vulcanstrace audit --intent FullAudit --role Server --notify-on-critical

# Export a MITRE ATT&CK Navigator layer from the audit findings
vulcanstrace audit --intent FullAudit --output-mitre /tmp/mitre-layer.json

# Check exit code
# 0 = success, no critical findings
# 1 = error
# 2 = success with critical findings
# 3 = auto-fix executed but some remediation commands failed
```

## Headless Audit with Auto-Fix

```bash
# Dry-run: preview what would change
vulcanstrace audit --intent FullAudit --auto-fix --dry-run

# Apply safe fixes after confirmation
vulcanstrace audit --intent FullAudit --auto-fix --yes

# Permit service restarts and package operations
vulcanstrace audit --intent FullAudit --auto-fix --yes --allow-restart --allow-packages
```

## Live Stream — Real-Time Kernel Telemetry

VulcansTrace can capture and analyze live network events in real time:

1. Open the **Live Stream** tab in the Avalonia UI.
2. Select a source:
   - **Synthetic Demo Stream** — works without root; generates realistic port scans, beaconing, and floods.
   - **Kernel Packet Capture** — requires root or `CAP_NET_RAW`; captures all IPv4 TCP/UDP packets via `AF_PACKET` + classic BPF.
   - **NFLOG Netlink** — requires root or `CAP_NET_ADMIN`; reads structured firewall events from netfilter NFLOG.
3. Select an analysis intensity (Low, Medium, High).
4. Click **Start**.
5. Watch the metrics panel (events/sec, window size, analysis runs, delta findings).
6. New findings appear in the live findings grid and are also added to the main findings grid.
7. Click **Stop** for graceful async shutdown.

### Setting up NFLOG

If using the NFLOG source, create an NFLOG rule first:

```bash
# iptables
sudo iptables -A INPUT -j NFLOG --nflog-group 1

# nftables
sudo nft add rule ip filter input log group 1
```

## Log Diff Mode

Compare two firewall logs to detect what changed between a baseline and an incident:

### CLI

```bash
# Basic diff with narrative output
vulcanstrace diff --baseline VulcansTrace.Linux.Tests/Data/Real/Samples/iptables-attack.log --incident VulcansTrace.Linux.Tests/Data/Real/Samples/iptables-attack.log --intensity Medium

# Export standalone reports
vulcanstrace diff --baseline baseline.log --incident incident.log --intensity High --output-json diff.json --output-html diff.html

# Include in signed evidence bundle
vulcanstrace diff --baseline baseline.log --incident incident.log --intensity Medium --output-evidence diff-evidence.zip
```

### Avalonia UI

1. Launch the app: `dotnet run --project VulcansTrace.Linux.Avalonia`
2. Click **Compare Logs** below the main Analyze button.
3. Select a **Baseline** file and an **Incident** file.
4. The app analyzes both files using the currently selected intensity and opens a **Log Diff** results window.
5. Review the **Connection Patterns** grid for per-pattern changes (count deltas, action shifts) and the **Findings** grid for severity changes or new/removed findings.
6. Use the CLI `diff` command for JSON/HTML output or signed evidence bundles.

## Performance and Profiling

```bash
# Benchmark default sizes (100, 500, 1000, 5000 lines)
dotnet run --project VulcansTrace.Linux.PerformanceConsole

# Run profiling mode
dotnet run --project VulcansTrace.Linux.PerformanceConsole -- profile
```
