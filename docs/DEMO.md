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

- Check the **Findings** tab for detected threats
- Switch to **Timeline** to visualize events over time with time-scaled bars per category
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

## Security Agent — Interactive Remediation

After running any audit, you can ask the agent to walk you through fixing a specific finding:

1. Run an audit: `Check my firewall`
2. When findings appear, type: `Fix FW-001`
3. The agent returns an interactive remediation card with:
   - **Preconditions** — checklist items such as "Root or sudo access" and "Console access available"
   - **Backup commands** — run these first to preserve state (e.g., `iptables-save`)
   - **Apply commands** — step-by-step fix commands, each with a safety badge
   - **Rollback commands** — how to undo if something goes wrong
   - **Verification commands** — confirm the fix worked
4. Review each command before copying and running it. Safety badges classify every command as `ReadOnly`, `ConfigChange`, `ServiceRestart`, `PackageInstall`, `Destructive`, or `Unknown`, plus structural warnings (`SUDO`, `CHAIN`, `PIPE`, `REDIR`, `DL-EXEC`).
5. If the finding's explanation template lacks rollback guidance for risky commands, the plan is blocked for safety and the agent tells you why.

## Security Agent — Auto-Fix (Batch Remediation)

The headless CLI can automatically remediate multiple findings after an audit:

1. Preview what would change without executing:
   ```bash
   vulcanstrace audit --intent FullAudit --auto-fix --dry-run
   ```
   The output shows which commands would execute, which would be skipped by policy, and any validation warnings.

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

## Performance and Profiling

```bash
# Benchmark default sizes (100, 500, 1000, 5000 lines)
dotnet run --project VulcansTrace.Linux.PerformanceConsole

# Run profiling mode
dotnet run --project VulcansTrace.Linux.PerformanceConsole -- profile
```
