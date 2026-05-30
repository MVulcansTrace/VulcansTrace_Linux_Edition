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

## Performance and Profiling

```bash
# Benchmark default sizes (100, 500, 1000, 5000 lines)
dotnet run --project VulcansTrace.Linux.PerformanceConsole

# Run profiling mode
dotnet run --project VulcansTrace.Linux.PerformanceConsole -- profile
```
