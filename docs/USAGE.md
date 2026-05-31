# Usage

## Avalonia UI

1. Launch the app with `dotnet run --project VulcansTrace.Linux.Avalonia`.
2. Paste iptables or nftables log text into the main input area.
3. Select a scan intensity:
   - **Low - Critical Threat Triage** — conservative thresholds, fewer findings.
   - **Medium - Investigation Review** — balanced thresholds for standard investigations.
   - **High - Deep Hunt / Forensics** — aggressive thresholds for deep hunts and forensics.
4. Select a machine role from the dropdown (Workstation, Server, LabBox, Router, DevMachine). The role affects which rules are enforced and how strictly they are evaluated.
5. Click **Analyze** to generate findings.
6. Review results:
   - **Findings tab** — searchable, filterable table of all detected threats. Use the search box and severity dropdown to narrow results.
   - **Timeline tab** — visual timeline of findings by category.
   - **Parse Errors tab** — lines that could not be parsed.
   - **Warnings tab** — analysis notices (truncation, caps, etc.).
   - **Compliance tab** — CIS Compliance Scorecard showing overall pass/warn/fail status, per-control-family breakdown, score percentage, and a trend chart of previous audits.
7. Use **Export Evidence** to save a cryptographically-signed ZIP bundle.

### Security Agent Panel

The Avalonia UI also includes a collapsible **Security Agent** panel. It can answer local posture questions such as:

- `Is my system secure?`
- `Check my firewall`
- `What ports are open?`
- `What services are running?`
- `Who am I talking to?`
- `Check my SSH`
- `Check file permissions`
- `Check my filesystem`
- `Any SUID binaries?`
- `Check my kernel hardening`
- `Check my user accounts`
- `Explain FW-001`
- `Fix FW-001`

After an audit, you can also ask follow-up questions without re-running scans:

- `What changed since the last audit?`
- `Why is this critical?`
- `Show only firewall issues`
- `Show only kernel issues`
- `Show only file permission issues`
- `Show only filesystem issues`
- `Show only user account issues`
- `What should I fix first?`
- `Fix FW-001` — interactive, step-by-step guided remediation for a specific finding
- `Which findings are suppressed?`

### Baseline & Drift Detection

The agent can snapshot a "known good" baseline and continuously monitor for drift:

- **`Set baseline`** — saves the last audit as a named baseline for its intent (e.g., FullAudit, FirewallCheck). Baselines are persisted to `~/.config/VulcansTrace/baselines.json` when available, with an in-memory fallback.
- **`Check drift`** — re-runs the audit for the baseline's intent and compares live findings against the saved snapshot. Drift results show new and worsened findings as actionable `Drift` entries, with a narrative summary. The user's previous audit context is preserved so follow-up questions still work.
- **`Show baseline`** — displays the saved baseline findings with their original details, categories, and fingerprints preserved.

Baselines are intent-scoped: you can have one active baseline per intent (FullAudit, FirewallCheck, SSHCheck, FilePermissionCheck, FilesystemAuditCheck, KernelCheck, UserAccountCheck, etc.). Setting a new baseline for an intent automatically activates it and deactivates any previous baseline for that same intent. Baseline names default to `Intent-Timestamp` but can be customized when set via chat (`set baseline MyName`).

The panel also includes quick-action buttons for common audits (full audit, firewall, ports, services, network, SSH, file permissions, kernel hardening), selected-finding explanation, exporting the latest agent audit through the shared evidence ZIP workflow, exporting a review-only remediation plan, and comparing either the latest two audits or two selected history entries. Remediation exports include preconditions, backup commands, apply commands, rollback commands or hints, and verification commands; risky or unclassified apply/backup commands must have explicit rollback guidance before the plan can be exported. Audit comparisons open with a deterministic narrative summary of what changed before the detailed counts and match findings by stable fingerprint, with rule-ID/target fallback for older history entries. Audit history is persisted when possible and keeps the latest 50 lightweight snapshots by default. Agent audit findings are loaded into the main findings grid, where they can be selected for explanation or marked as accepted risk. The Coverage tab shows passed, active failed, suppressed, and crashed rule checks by category after an agent audit. The Compliance tab shows the CIS Compliance Scorecard with an overall score badge, per-family DataGrid, and a mini bar-chart trend visualization. The chat shows a data-source capability report for local scanner inputs such as iptables, nftables, ss, netstat, ip, systemctl, and sshd, including permission-limited sources. Accepted-risk suppressions are fingerprint-scoped when possible and can be set for 7, 30, or 90 days, or permanently; expired suppressions stop applying immediately, remain visible in the suppression review queue for 30 days, and are then pruned during audits. Legacy suppressions without fingerprints still match by rule ID and target. Suppressions are persisted when possible; if persistence is unavailable, the UI reports that suppressions are session-only.

The right-side Suppressions tab shows entries needing review, including items expiring soon, recently expired suppressions, permanent suppressions, and stale permanent suppressions. From that queue you can renew, convert duration, edit the reason, or remove the suppression.

Agent chat findings can be filtered by severity and category without changing the underlying audit result. Copyable verification commands include safety badges such as ReadOnly, ConfigChange, ServiceRestart, PackageInstall, Destructive, or Unknown, plus inline SUDO, CHAIN, PIPE, REDIR, and DL-EXEC badges when those command structures are detected.

**Interactive Remediation** — When you type `fix FW-001` after an audit, the agent returns a guided remediation card for that specific finding. The card shows preconditions as a checklist, then backup commands (run these first to preserve state), apply commands (the step-by-step fix), rollback commands (if something goes wrong), and verification commands (confirm the fix worked). Every command carries the same safety and structural badges as verification commands. The agent validates the plan before displaying it: risky or unclassified commands without explicit rollback guidance are blocked for safety.

The agent reads local host state through Linux tools such as `iptables`, `nft`, `ss`, `netstat`, `systemctl`, and `ip`. It reports scanner permission or availability issues as warnings and as a capability report that is also included in Markdown and HTML evidence exports. The main log input is shared with the agent, so pasted firewall logs can be included when the agent runs log analysis.

For the full capability list and limitations, see [Security Agent](SECURITY_AGENT.md).

## Recurring Audit Scheduling

VulcansTrace supports automatic recurring audits through the system `crontab`. Schedules can be created and managed from both the GUI and the headless CLI.

### GUI Schedule Editor

The Avalonia UI includes a **Schedules** tab:

1. Open the **Schedules** tab.
2. Click **Add** to create a new schedule, or select an existing schedule and click **Edit**.
3. Fill in the schedule details:
   - **Name** — a unique, human-friendly name.
   - **Intent** — the audit intent to run (FullAudit, FirewallCheck, etc.).
   - **Cron Expression** — a standard 5-field cron expression (e.g., `0 6 * * *` for daily at 06:00).
   - **Machine Role** — the role used when running the audit.
   - **Output Directory** — optional directory to write JSON audit results.
   - **Notification Channel** — Desktop, Email, or Webhook.
   - **Notify on critical findings** — whether to send a notification when new critical findings appear.
   - **Enabled** — whether the schedule is active.
4. Click **Save**. The schedule is persisted to `~/.config/VulcansTrace/schedules.json`.
5. Select a schedule and click **Install in Cron** to register it with the system crontab. The schedule must be enabled to install.
6. Click **Run Now** to execute a schedule on demand. The result is persisted to the audit history store.
7. The grid shows whether each schedule is currently installed in cron.

### CLI Schedule Management

The headless CLI provides full schedule management:

```bash
# List all schedules
vulcanstrace schedule list

# Add a schedule
vulcanstrace schedule add --name "Daily Full Audit" --intent FullAudit --cron "0 6 * * *" --role Server --notify-on-critical --channel Desktop

# Edit a schedule
vulcanstrace schedule edit --id <schedule-id> --cron "0 7 * * 1" --channel Email

# Enable / disable a schedule
vulcanstrace schedule enable --id <schedule-id>
vulcanstrace schedule disable --id <schedule-id>

# Install into system crontab
vulcanstrace schedule install-cron --id <schedule-id>

# Remove from system crontab
vulcanstrace schedule uninstall-cron --id <schedule-id>

# Run a scheduled audit immediately (also used by cron)
vulcanstrace schedule run --id <schedule-id>

# Delete a schedule
vulcanstrace schedule delete --id <schedule-id>
```

Scheduled audits compare critical findings against the previous audit's fingerprints and only notify when **new** critical findings appear. This prevents alert fatigue from recurring known issues.

### Cron Expression Format

Standard 5-field Linux cron:

```
minute hour day-of-month month day-of-week
```

Examples:

| Expression | Meaning |
|------------|---------|
| `0 6 * * *` | Daily at 06:00 |
| `0 6 * * 1` | Weekly on Monday at 06:00 |
| `0 */6 * * *` | Every 6 hours |
| `30 2 1 * *` | Monthly on the 1st at 02:30 |

The CLI and GUI both validate cron expressions before saving.

## Headless CLI Audits

Run audits without launching the desktop UI:

```bash
vulcanstrace audit --intent FullAudit --role Server --notify-on-critical
```

Exit codes:
- `0` — success, no critical findings.
- `1` — error.
- `2` — success with critical findings.

## Notifications

When a scheduled audit produces new critical findings, a notification is sent through the configured channel. Notification failures are logged to `stderr` and do not affect the audit exit code.

### Desktop Notifications

Uses `notify-send` (Linux desktop notification daemon). Falls back silently if unavailable.

### Email Notifications

Configure via environment variables:

```bash
export VT_EMAIL_SMTP_HOST=smtp.example.com
export VT_EMAIL_SMTP_PORT=587
export VT_EMAIL_FROM=vulcanstrace@example.com
export VT_EMAIL_TO=security@example.com
export VT_EMAIL_USER=username      # optional
export VT_EMAIL_PASS=password      # optional
export VT_EMAIL_NO_SSL=1           # set to 1, true, or yes to disable SSL
```

### Webhook Notifications

Configure via environment variable:

```bash
export VT_WEBHOOK_URL=https://hooks.example.com/vulcanstrace
```

The webhook receives a JSON POST with `title`, `message`, `scheduleName`, `criticalCount`, and `timestamp`. Failed requests are retried up to 3 times with exponential backoff for transient errors (5xx, timeouts, connection failures).

## Rule Tuning / Local Policy

The agent supports per-machine-role rule tuning via a local policy file. Roles are:

- **Workstation** — laptops and desktops.
- **Server** — production servers and bastion hosts.
- **LabBox** — test and lab machines.
- **Router** — network gateways and appliances.
- **DevMachine** — development workstations with extra services.

Rules can be stricter or looser depending on the role. For example:
- `PORT-001` (SSH on default port) is stricter on **Server** and looser on **Workstation**.
- `PORT-002` (wide-open services) allows extra ports such as `8080` on **DevMachine**.
- `SRV-005` (unnecessary services) ignores `nfs` and `smb` on **DevMachine**.

Policies are stored in `~/.config/VulcansTrace/policy.json` and can override:
- `enabled` — skip a rule entirely.
- `severityOverride` — change the severity when a rule fails.
- `autoPass` — treat a failure as passed (looser).
- `parameters` — rule-specific key/value pairs for contextual rules.

Example `policy.json`:

```json
{
  "DevMachine": {
    "PORT-002": {
      "parameters": {
        "expectedPublicPorts": "22,80,443,8080,8443"
      }
    },
    "SRV-005": {
      "parameters": {
        "ignoredServices": "nfs,smb"
      }
    }
  }
}
```

Built-in defaults are provided for tuned rules and roles; user-supplied policies in the JSON file take precedence and inherit any built-in parameters they do not replace.

## Evidence Export

Exporting evidence produces a ZIP archive with:
- `findings.csv`
- `findings.json`
- `findings.stix.json`
- `report.html`
- `summary.md`
- `log.txt`
- `suppressions.csv` when active accepted-risk suppressions exist
- `manifest.json` — file hashes, skipped line count, and parse error details
- `manifest.hmac` — HMAC-SHA256 signature for integrity verification

The signing key is generated per analysis session and masked in the UI. Re-running analysis creates a new key; repeated exports of the same result reuse the session key. Copy and store it if you need to verify the bundle later.

Bundles can be verified end-to-end using the built-in Verify API, which checks the HMAC signature and recomputes SHA-256 hashes for every file in the manifest.

Suppression notes include the rule ID, target, reason, expiry/review dates, and finding fingerprint when one is available, so accepted-risk evidence can be traced back to the exact posture finding that was suppressed.

The optional CLI runner can verify a saved evidence bundle when you provide the copied signing key:

```bash
dotnet run --project tools/TestAnalysis -- --verify evidence.zip --key <64-character-hex-key>
```

See `docs/HMAC_EVIDENCE.md` for the step-by-step HMAC signing key flow.

## Supported Log Formats

- iptables kernel logs (typically from `/var/log/kern.log`).
  - Action is inferred from the log prefix if `ACCEPT`, `DROP`, or `REJECT` is present.
- nftables kernel logs (lines containing `nf_tables:`).
  - Action is inferred from the chain name if it includes `ACCEPT`, `DROP`, or `REJECT`.
- Mixed-format logs are handled automatically — lines are classified individually.

## Limits and Warnings

- Log input is capped at 100,000,000 characters.
- Parse errors are captured in analysis results, with up to 500 retained.
- Each detector is capped at 100 findings per category. If a detector exceeds this, a truncation warning is emitted.
- Some detectors may also emit warnings when individual analysis windows are truncated (for example, port scan event caps).

## CLI Test Tool

The optional CLI runner in `tools/TestAnalysis` (not in the solution file) can analyze a log file directly:

```bash
dotnet run --project tools/TestAnalysis -- VulcansTrace.Linux.Tests/Data/Real/Samples/iptables-attack.log
```

It can also export and verify evidence bundles:

```bash
dotnet run --project tools/TestAnalysis -- VulcansTrace.Linux.Tests/Data/Real/Samples/iptables-attack.log --export /tmp/vulcan-evidence --intensity Medium
dotnet run --project tools/TestAnalysis -- --verify /tmp/vulcan-evidence/iptables-attack_Medium.zip --key <printed-signing-key>
```

## Building a Self-Contained CLI Binary

```bash
./scripts/publish-cli.sh
```

This produces a self-contained `linux-x64` binary at `artifacts/publish/vulcanstrace` that can be copied to target systems without requiring the .NET runtime.
