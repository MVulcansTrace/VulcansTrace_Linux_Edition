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
   - **Findings tab** — searchable, filterable table of all detected threats. Use the search box and severity dropdown to narrow results. The **MITRE ATT&CK** column shows mapped techniques for each finding.
   - **Timeline tab** — visual timeline of findings by category. Toggle **Trace Map** to draw directed correlation edges between related findings (escalation, temporal sequence, same-host links). Toggle **Group by Host** to re-group the Y-axis by source host instead of category. Click any finding bar to highlight its connected attack chain; a narrative panel appears below the timeline describing the chain. If more than 100 edges are detected, interactive rendering is suppressed for performance — export the evidence bundle to review the full Trace Map.
   - **Incident Story tab** — flowing attack narrative generated from findings and correlations. Shows a time-ordered timeline, the likely attack chain (e.g., "C2 → Lateral Movement → Privilege Escalation"), context-aware recommended responses, and a **Copy Markdown** button for one-click export of the narrative.
   - **Parse Errors tab** — lines that could not be parsed.
   - **Warnings tab** — analysis notices (truncation, caps, etc.).
   - **Compliance tab** — CIS Compliance Scorecard showing overall pass/warn/fail status, per-control-family breakdown, score percentage, and a trend chart of previous audits.
   - **Risk Score tab** — aggregate Risk Scorecard showing a color-coded grade badge (A–F), numeric score (0–100), summary status, and a per-category breakdown ordered by total deduction.
   - **Doctor tab** — self-diagnostic view that probes every local Security Agent scanner and lists which data sources are available, unavailable, permission-limited, or not checked. Shows a summary status banner and a warnings banner when scanners encounter command failures or permission limits.
7. Use **Export Evidence** to save a cryptographically-signed ZIP bundle.

### Security Agent View

The Avalonia UI includes a first-class **Security Agent** view in the main navigation sidebar. It can answer local posture questions such as:

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
- `Check my logging`
- `Check my syslog`
- `Check my cron jobs`
- `Check package vulnerabilities`
- `Check my containers`
- `Check my kubernetes`
- `Check my pods`
- `Explain FW-001`
- `Prove FW-001` / `Show evidence for FW-001`
- `Fix FW-001`
- `Remediate FW-001`
- `Verify remediation abc12345`
- `List my sessions` / `Show sessions`
- `Resume session abc12345`
- `Add note to session abc12345 <text>` — append a free-text note to a remediation session
- `Note for step FW-001 in session abc12345 <text>` — append a note to a specific step within a session

The view also provides faster paths for common actions:

- **Slash commands** — type `/` in the query box to open a palette of quick intents. Examples: `/firewall`, `/network`, `/ports`, `/services`, `/ssh`, `/filesystem`, `/kernel`, `/users`, `/logging`, `/cron`, `/packages`, `/containers`, `/kubernetes`, `/threatintel`, `/yara`, `/processes`, `/full`, `/fullaudit`, `/baseline`, `/drift`, `/baseline show`, `/show baseline`, `/sessions`, `/risk`, `/help`, `/clear`. Selecting a command immediately runs the corresponding audit or follow-up.
- **Quick-action chips** — clickable chips above the query box for common audits (`Full audit`, `Firewall`, `Ports`, `Services`, `Network`, `Containers`, `Kubernetes`, `YARA`, `Processes`) and follow-ups (`Set baseline`, `Check drift`, `Show baseline`, `Export audit`).
- **Markdown rendering** — `**bold**` and `*italic*` markup in agent messages is rendered as styled inlines.
- **User-friendly warnings** — scanner warnings are classified and surfaced in plain language (missing tool, permission denied, configuration missing, scanner error) instead of raw strings.
- **Copyable command rows** — verification, backup, apply, rollback, and verification commands render in rows with one-click copy and safety/structure badges.

The agent composes narrative responses from findings, posture correlations, per-rule memory, system trajectory, proactive alerts, relationship-backed attack chains, and remediation wisdom:

- `Is my system secure?` — produces a multi-paragraph narrative with summary, key findings, combined risk, system trajectory, proactive alerts, attack chains, remediation patterns, continuity, and next steps.
- `Explain FW-001` — the explanation depth adapts to the rule's history:
  - First time you ask, or with no history, you get the concise structured explanation (what was found, why it matters, how to verify, next action).
  - After the rule has been retained in multiple audit snapshots, a **History** paragraph notes when it was first seen and whether it is stable, improving, or worsening.
  - After two or more completed remediation cycles, a **Root cause** paragraph adds category-specific guidance (for example, firewall rules that keep reverting often point to a startup script or config-management tool).
  - If the severity is escalating, a **What changed** paragraph traces the severity timeline so you can compare the current finding to previous audits.
- `Prove FW-002` / `Show evidence for it` (after explaining a finding) — shows the evidence chain: which scanner and command produced the finding, raw evidence signals, cross-scanner validation, rule evaluation, CIS/MITRE context, attack-chain membership, and per-rule history. If the rule is currently passing, the agent says so explicitly instead of reporting a missing finding.
- `Check my SSH` — when both `FW-002` and `SSH-002` fire, the narrative explains that password-based SSH exposed to the internet creates a straight path to root.
- `Is my system secure?` after multiple audits — may include a trajectory paragraph such as "Across your recent audits, the system is trending worsening. 2 rule(s) worsening (SSH-002, SSH-001), 1 rule(s) improving (KERN-001)."
- After a verified fix returns — the narrative includes a proactive alert such as "[SSH-002] returned after being verified fixed 3 days ago. Something re-applied the insecure configuration..."
- When a posture correlation has a continuation-graph path — the narrative renders an ordered path such as "This is one attack chain: [FW-002] SSH is exposed to the internet, making the host visible to scanning and reconnaissance campaigns (T1562.004) → [SSH-002] Password authentication allows remote brute-force attempts against the exposed SSH service (T1021.004, T1110) → [SSH-001] PermitRootLogin allows an attacker who obtains root credentials to execute commands as root directly (T1021.004, T1110). Fix any one link and the chain breaks."
- After repeated fix-and-return cycles — the narrative renders a remediation pattern such as "[SSH-002] has been fixed and returned 3 times. A one-time fix won't hold here. You likely have a config-management tool (Ansible, cloud-init) re-applying the insecure SSH setting. Check your playbooks."
- `What should I fix first?` — returns a severity-ordered remediation plan; if a correlated pair such as `FW-002` + `SSH-002` exists, the agent suggests fixing them together.

Proactive suggestion chips also appear automatically:

- After an audit with correlated findings — `Fix FW-002 and SSH-002 together`.
- After a finding has been open for 7+ days — `Prioritize FW-001 — still open`.
- After verifying a session where a correlated finding remains — `Fix related SSH-002`.
- After a targeted audit with unchecked categories remaining — `Check filesystem security`, `Check user accounts`, `Check running processes`, etc.

The agent also keeps a long-horizon **category coverage map** across sessions. A `FullAudit` marks all 17 audit categories as checked; each targeted audit marks one category. When you run a partial audit and other categories remain unchecked, the narrative includes a coverage note such as:

> **Coverage note:** You've audited Firewall and SSH. You haven't checked Network, Service and Port, plus 12 more yet. Running those checks would reduce your blind spots.

Coverage is preserved across `Check drift`, `Verify remediation`, `Verify finding`, and category-filter fallback audits, so these operations do not reset your cumulative view. It is stored in the same `agent-memory.json` snapshot as rule history and conversation context.

After an audit, you can also ask follow-up questions without re-running scans:

- `What changed since the last audit?`
- `Why is this critical?`
- `Show only firewall issues`
- `Show only kernel issues`
- `Show only file permission issues`
- `Show only filesystem issues`
- `Show only user account issues`
- `Show only cron job issues`
- `Show only package vulnerability issues`
- `Show only container issues`
- `Show only kubernetes issues`
- `What should I fix first?`
- `Fix FW-001` — single-finding remediation preview when rollback guidance is present. No session or timeline is created.
- `Remediate FW-001` — persisted guided remediation session with step tracking, timeline, verification, and export
- `Verify remediation abc12345` — before/after verification for an active remediation session; blocked or failed verification is recorded in the session timeline
- `List my sessions` / `Show sessions` — lists all persisted remediation sessions with ID, status, rule ID, and creation time
- `Resume session abc12345` — reloads a previously saved remediation session into the chat panel for review or continued verification
- `Verify finding FW-001` — re-run the original audit intent and verify whether a specific rule is still failing
- `Which findings are suppressed?`
- `What's my risk grade?` — returns the aggregate Risk Scorecard after an audit
- `Risk score` — alias for the above

### Baseline & Drift Detection

The agent can snapshot a "known good" baseline and continuously monitor for drift:

- **`Set baseline`** — saves the last audit as a named baseline for its intent (e.g., FullAudit, FirewallCheck). Baselines are persisted to `~/.config/VulcansTrace/baselines.json` when available, with an in-memory fallback.
- **`Check drift`** — re-runs the audit for the baseline's intent and compares live findings against the saved snapshot. Drift results show new and worsened findings as actionable `Drift` entries, with a narrative summary. The user's previous audit context is preserved so follow-up questions still work. Support-only `Low` ↔ `Medium` confidence transitions are treated as unchanged (they typically reflect scanner-availability churn, such as `ss` becoming permission-limited), while contradiction-driven confidence drops still surface.
- **`Show baseline`** — displays the saved baseline findings with their original details, categories, and fingerprints preserved.

Baselines are intent-scoped: you can have one active baseline per intent (FullAudit, FirewallCheck, SSHCheck, FilePermissionCheck, FilesystemAuditCheck, KernelCheck, UserAccountCheck, LoggingAuditCheck, CronJobCheck, PackageVulnerabilityCheck, ContainerCheck, KubernetesCheck, ThreatIntelCheck, YaraCheck, etc.). Setting a new baseline for an intent automatically activates it and deactivates any previous baseline for that same intent. Baseline names default to `Intent-Timestamp` but can be customized when set via chat (`set baseline MyName`).

The panel also includes quick-action buttons for common audits (full audit, firewall, ports, services, network, containers, kubernetes), selected-finding explanation, exporting the latest agent audit through the shared evidence ZIP workflow, exporting a review-only remediation plan, exporting the latest guided remediation session report, comparing either the latest two audits or two selected history entries, and viewing the Risk Scorecard. Remediation exports include an impact preview block, preconditions, backup commands, apply commands, rollback commands or hints, and verification commands; risky or unclassified apply/backup commands must have explicit rollback guidance before the plan can be exported. Session exports include session ID, step state, blocked reasons, before snapshot, remediation plan, verification diff when present, and a chronological timeline of session events. The session timeline records successful exports only after the markdown file is written; cancelling the save dialog or hitting a write error leaves the timeline unchanged. Audit comparisons open with a deterministic narrative summary of what changed before the detailed counts and match findings by stable fingerprint, with rule-ID/target fallback for older history entries. Audit history is persisted when possible and keeps the latest 50 lightweight snapshots by default; the newest 5 are fully detailed and older retained entries are slimmed to counts, findings, and scorecards to keep the file bounded. Agent audit findings are loaded into the main findings grid, where they can be selected for explanation or marked as accepted risk. The Coverage tab shows passed, active failed, suppressed, and crashed rule checks by category after an agent audit. The Compliance tab shows the CIS Compliance Scorecard with an overall score badge, per-family DataGrid, and a mini bar-chart trend visualization. The Risk Score tab shows the aggregate Risk Scorecard with a grade badge, numeric score, summary status, and per-category breakdown. The chat shows a data-source capability report for local scanner inputs such as iptables, nftables, ss, netstat, ip, systemctl, sshd, docker, crictl, ctr, and kubectl, including permission-limited sources. Accepted-risk suppressions are fingerprint-scoped when possible and can be set for 7, 30, or 90 days, or permanently; expired suppressions stop applying immediately, remain visible in the suppression review queue for 30 days, and are then pruned during audits. Legacy suppressions without fingerprints still match by rule ID and target. Suppressions are persisted when possible; if persistence is unavailable, the UI reports that suppressions are session-only.

The right-side Suppressions tab shows entries needing review, including items expiring soon, recently expired suppressions, permanent suppressions, and stale permanent suppressions. From that queue you can renew, convert duration, edit the reason, or remove the suppression.

Agent chat findings can be filtered by severity and category without changing the underlying audit result. Copyable verification commands include safety badges such as ReadOnly, ConfigChange, ServiceRestart, PackageInstall, Destructive, or Unknown, plus inline SUDO, CHAIN, PIPE, REDIR, and DL-EXEC badges when those command structures are detected.

**Interactive Remediation Preview** — When you type `fix FW-001` after an audit, the agent returns a single-finding remediation card when the finding's explanation includes enough rollback guidance. The card opens with a compact **Impact Preview** panel summarizing the expected impact, rollback path, verification command, risk before/after, command count, rollback availability, restart impact, and lockout risk before the detailed command lists. Below that, preconditions are shown as a checklist, then backup commands (run these first to preserve state), apply commands (the step-by-step fix), rollback commands (if something goes wrong), and verification commands (confirm the fix worked). Every command carries the same safety and structural badges as verification commands. The agent validates the plan before displaying it: risky or unclassified commands without explicit rollback guidance are blocked for safety and the command card is not shown.

**Guided Remediation Sessions** — When you type `remediate FW-001`, the agent creates a persisted manual session with a short session ID, a before snapshot, step state, an immutable event timeline, and a Verify Remediation button. The timeline records session creation, step state changes, blocked steps, verification lifecycle events, failed verification attempts, successful report exports, and session/step notes. After you complete the manual steps, click **Verify Remediation** or type `verify remediation <session-id>` to re-run the original audit intent and produce a before/after diff. Blocked sessions remain visible with their safety reasons and timeline but cannot be verified as completed remediation. Use **Export Session** to save a markdown report that includes the timeline and any notes for review or audit handoff; the export event is recorded only after the report is written successfully.

**Step-Outcome Reporting** — While a remediation session is active, you can report what happened after each manual step instead of jumping straight to verification. The agent recognizes explicit outcome language and updates the session timeline automatically. Examples:

- `step 1 worked` / `step 1 done` / `step 1 completed`
- `step 2 failed` / `step 2 didn't work` / `step 2 did not work`
- `it worked` / `that worked` / `it failed` / `that didn't work`
- `step 2 failed with permission denied`
- `step 1 failed because service auditd is not installed`

You can reference the step by ordinal (`step 2`), rule ID (`FW-001 failed`), or session ID (`step 1 worked in session abc12345`). On success, the agent marks the step complete and either prompts for the next step or suggests verification. On failure, it classifies the failure category (permission issue, missing dependency, missing service, malformed command, already configured/conflicting setting, or unknown) and returns adaptive, rule-aware guidance — for example, retrying with `sudo`, installing a prerequisite package, enabling a missing service, or reviewing a conflicting setting. These responses are deterministic; no external model is consulted.

**Session Notes** — During an existing remediation session, you can append free-text notes for audit traceability:
- `add note to session abc12345 <text>` — adds a session-level note.
- `note for step FW-001 in session abc12345 <text>` — adds a step-level note tied to a specific rule.

Notes support lightweight evidence syntax: wrap references in brackets (`[ticket-SEC-123]`) or backticks (`` `screenshot-2026-06-02` ``) and they are automatically extracted into traceable evidence links and stripped from the displayed text. Notes are append-only, recorded as `SessionNoteAdded` or `StepNoteAdded` timeline events, and included in exported session markdown under a dedicated **Notes** section.

**Remediation Session Management** — The Agent view includes a persisted-session browser with refresh, resume, and delete actions. Chat commands `list my sessions` / `show sessions` list persisted sessions with their ID, status, rule ID, and creation time, and `resume session <id>` reloads a session into the chat panel.

**Automated Incident Response Playbooks** — When `TraceMapCorrelator` detects a critical attack chain (Beaconing → LateralMovement → PrivilegeEscalation on the same host), the Security Agent view surfaces an active countermeasure card:

1. A chat message appears describing the critical chain with the attacker's C2 IP, compromised host, and a **Deploy Countermeasures** button.
2. Click **Deploy Countermeasures** to start the workflow:
   - **Dry-run preview** — the system builds the remediation plan, validates the attacker IP, and shows what commands would execute without making any changes. Results are posted to chat.
   - **Confirmation dialog** — if the dry-run succeeds, a dialog asks `Deploy Live` or `Cancel`.
   - **Live execution** — if confirmed, the executor runs backup commands first, then applies the countermeasures (firewall DROP + tagged auditd connect telemetry), then verifies the firewall rule is active using an exact rule check.
3. If the attacker IP is invalid, the plan is blocked with a `COUNTERMEASURE-BLOCKED` section and a clear risk note — no shell commands are generated.
4. If multiple critical chains target the same attacker IP, only one countermeasure section is created (deduplicated by IP).
5. Safety properties:
   - Attacker IP parsed and validated before command generation
   - Auditd telemetry is tagged for correlation; the firewall rule performs the IP-specific enforcement
   - Verification uses an exact firewall rule check, not `grep`
   - Commands feed through bash stdin (not `-c` wrapping) to prevent injection
   - Dry-run always runs first; live deployment requires explicit confirmation

The agent reads local host state through Linux tools such as `iptables`, `nft`, `ss`, `netstat`, `systemctl`, and `ip`. It reports scanner permission or availability issues as warnings and as a capability report that is also included in Markdown and HTML evidence exports. The main log input is shared with the agent, so pasted firewall logs can be included when the agent runs log analysis.

For the full capability list and limitations, see [Security Agent](SECURITY_AGENT.md).

## Recurring Audit Scheduling

VulcansTrace supports automatic recurring audits through the system `crontab`. Schedules can be created and managed from both the GUI and the headless CLI. Every CLI command also accepts the global flag `--config-dir <dir>` to override the default `~/.config/VulcansTrace` directory.

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
   - **Autonomous drift response** — whether to automatically check for baseline drift after the scheduled audit and send a signed alert when drift at or above the threshold is detected.
   - **Autonomous drift threshold** — severity threshold (Critical, High, Medium, Low, Info) that must be met or exceeded before an autonomous drift alert is sent.
   - **Require signed alerts** — when enabled, drift alerts are skipped if `VT_ALERT_SIGNING_KEY` is not configured.
   - **Allow remediation** — enables a human-approved remediation path from drift alerts.
   - **Allow remediation restart** — permits remediation commands that restart services (requires Allow remediation).
   - **Allow remediation packages** — permits remediation commands that install or remove packages (requires Allow remediation).
   - **Remediation rule prefixes** — comma-separated rule-id prefixes (e.g., `FW, KERN`) that remediation may target. Empty means all rules.
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

# Add a schedule with autonomous drift response and signed alerts
vulcanstrace schedule add --name "Daily Firewall Check" --intent FirewallCheck --cron "0 6 * * *" \
  --autonomous-drift-response --autonomous-drift-threshold High --require-signed-alerts \
  --allow-remediate --remediation-prefixes FW

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

# Review and execute remediation for a schedule (human approval required)
vulcanstrace schedule remediate --id <schedule-id>           # preview + prompt
vulcanstrace schedule remediate --id <schedule-id> --dry-run # preview only
vulcanstrace schedule remediate --id <schedule-id> --yes     # skip confirmation prompt

# Delete a schedule
vulcanstrace schedule delete --id <schedule-id>
```

Scheduled audits compare critical findings against the previous audit's fingerprints and only notify when **new** critical findings appear. This prevents alert fatigue from recurring known issues.

When **autonomous drift response** is enabled, the scheduled audit also checks for baseline drift and sends a signed alert through the configured notification channel if drift at or above the threshold is detected. Set `VT_ALERT_SIGNING_KEY` to a 64-character hex HMAC key to sign alerts; without it, alerts are sent with the explicit `UNSIGNED` sentinel.

### Remediation Session Management (CLI)

The headless CLI can list, inspect, and delete persisted remediation sessions:

```bash
# List all sessions
vulcanstrace session list

# Show details for a specific session
vulcanstrace session show --id <session-id>

# Delete a session
vulcanstrace session delete --id <session-id>
```

Sessions are persisted to `~/.config/VulcansTrace/remediation-sessions.json` when available, with an in-memory fallback.

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

## Log Diff Mode

VulcansTrace can compare two firewall log files to detect changes in connection patterns and findings between a baseline and an incident timeframe.

### CLI Log Diff

```bash
# Compare two logs and print a narrative summary
vulcanstrace diff --baseline baseline.log --incident incident.log --intensity Medium

# Export diff results as standalone JSON and HTML
vulcanstrace diff --baseline baseline.log --incident incident.log --intensity Medium --output-json diff.json --output-html diff.html

# Include diff reports in a signed evidence bundle.
# If --signing-key is omitted, the CLI prints a generated key that must be saved for later verification.
vulcanstrace diff --baseline baseline.log --incident incident.log --intensity Medium --output-evidence diff-evidence.zip
```

Exit codes:
- `0` — no differences detected.
- `1` — error (missing files, invalid arguments, analysis failure).
- `2` — differences detected (new, removed, or changed events/findings).

### Avalonia UI Log Diff

1. Open the Avalonia UI.
2. Click **Compare Logs** (below the main Analyze button).
3. Select a **Baseline** log file and an **Incident** log file.
4. The app analyzes both files using the currently selected intensity and opens a **Log Diff** results window.
5. Review the diff results:
   - **Connection Patterns** — per-pattern comparison showing baseline count, incident count, delta, dominant actions, and diff state (`Unchanged`, `Added`, `Removed`, `Changed`). Source ports are wildcarded for matching so ephemeral-port churn does not split one pattern into fake add/remove rows.
   - **Findings** — per-fingerprint comparison showing new, resolved, changed, and unchanged findings.
   - **Summary** — narrative description of what changed, with counts for each state.
6. Use the CLI `diff` command when you need JSON/HTML output or a signed evidence bundle for handoff.

## Headless CLI Audits

Run audits without launching the desktop UI:

```bash
vulcanstrace audit --intent FullAudit --role Server --notify-on-critical
```

### Verify a Specific Finding

After manually remediating a finding, verify whether it is still detected:

```bash
vulcanstrace verify-finding FW-001
```

The CLI re-runs the original audit intent, reports whether the rule is still failing, and records `LastVerifiedFixedUtc` in the agent memory when the finding is resolved. If the same finding appears in a later audit, the agent closes the remediation cycle and renders a proactive alert. Actual remediation attempts are recorded as `LastRemediationAttemptUtc` and as pending remediation cycles after a guided session step is marked in progress, completed, or failed, or after live `--auto-fix` executes an apply command; timestamps and closed-cycle counts appear in the narrative if the rule is seen again later.

## Doctor — Data-Source Self-Diagnostic

The Doctor quickly probes every Security Agent scanner and reports which local data sources are accessible. It does not evaluate posture rules; it only checks scanner reachability so you can confirm visibility before running an audit.

### CLI Doctor

```bash
# Run the doctor diagnostic
vulcanstrace doctor

# Export the capability report as JSON
vulcanstrace doctor --output-json /tmp/vt-doctor.json
```

Exit codes:
- `0` — all normalized data sources reported `Available`.
- `1` — at least one normalized data source reported `Unavailable` or a runtime error occurred.
- `2` — at least one normalized data source reported `PermissionLimited` or `Unknown`, with none `Unavailable`.
- `130` — cancelled by the user (SIGINT).

The JSON output contains normalized `capabilities` entries (`sourceName`, string `status`, `detail`), the deterministic `capabilityReport` string used during audits, aggregate visibility counts, and a `warnings` array describing any command failures or permission limits encountered.

### Avalonia UI Doctor Tab

1. Open the **Doctor** tab.
2. Click **Run Diagnostic**.
3. Review the summary banner:
   - Green — every normalized data source reported `Available`.
   - Yellow — one or more scanners are `PermissionLimited`.
   - Red — one or more scanners are `Unavailable`.
4. Review the normalized capability grid showing source name, availability, and detail.
5. If any scanner produced a warning, a warnings banner appears with the command failure or permission message.

## Threat Intel Import (STIX / MISP)

VulcansTrace can import offline threat intelligence from STIX 2.1 bundles and MISP event JSON for correlation during audits and live stream analysis. Imported IOCs are persisted to `~/.config/VulcansTrace/threat-intel.json` (with an in-memory fallback) and checked against firewall logs, active connections, open ports, and file hashes.

### CLI Threat Intel Management

```bash
# Import a STIX 2.1 bundle (auto-detected)
vulcanstrace threat-intel import --file /path/to/stix-bundle.json

# Import with explicit format
vulcanstrace threat-intel import --file /path/to/iocs.json --format stix
vulcanstrace threat-intel import --file /path/to/iocs.json --format misp

# Show current IOC counts by type
vulcanstrace threat-intel status

# Clear all imported IOCs
vulcanstrace threat-intel clear
```

### Supported IOC Types

| IOC Type | STIX Source | MISP Source | Correlation Target |
|----------|-------------|-------------|-------------------|
| IPv4 address | `ipv4-addr` object, indicator pattern | `ip-dst`, `ip-src`, `ip-dst\|port` | Firewall logs, active connections |
| IPv6 address | `ipv6-addr` object, indicator pattern | `ip-dst`, `ip-src` | Firewall logs, active connections |
| Domain | `domain-name` object, indicator pattern | `domain`, `hostname` | Stored for future correlation¹ |
| URL | `url` object, indicator pattern | `url` | Stored for future correlation¹ |
| Port | `network-traffic:dst_port` / `src_port` pattern | `port`, `ip-dst\|port` | Open ports, firewall logs |
| File hash (SHA-256/MD5/SHA-1) | `file` hashes, indicator pattern | `sha256`, `md5`, `sha1`, `filename\|sha256` | SUID/SGID, world-writable, cron files |

¹ Domain and URL IOCs are imported and persisted, but firewall log correlation currently matches on IP addresses and ports only. Domain/URL correlation will be available when the log parser extracts those fields.

### Avalonia UI Import

The Security Agent view includes an **Import Threat Intel** button. Click it to open a file picker, select a STIX or MISP JSON file, and confirm the format. Imported IOCs are immediately available for correlation in the next audit or live stream session.

### How Threat Intel Correlation Works

1. **Import**: STIX/MISP parsers extract IOCs and store them in `IThreatIntelStore`.
2. **Log Analysis**: `ThreatIntelDetector` (Engine layer) checks every `UnifiedEvent` against stored IPs and ports. Matching events produce `FindingCategory.ThreatIntel` findings with severity mapped from IOC threat score.
3. **Posture Audit**: `ThreatIntelIpRule` (`TI-001`) checks active connections against IP IOCs. `ThreatIntelPortRule` (`TI-002`) checks open ports against port IOCs. `ThreatIntelHashRule` (`TI-003`) checks hashes of security-sensitive files (SUID/SGID, world-writable, cron scripts, unowned files) against hash IOCs. File hashing is skipped when no file-hash IOCs are loaded, so routine audits do not pay the disk-scanning cost unnecessarily.
4. **Threat Score Mapping**: IOC threat score `>= 80` → Critical, `>= 60` → High, `>= 40` → Medium, else Low.

### MITRE ATT&CK Navigator Layer Export

The CLI can export a MITRE ATT&CK Navigator layer JSON from configured detector/rule coverage and audit findings:

```bash
vulcanstrace audit --intent FullAudit --output-mitre /path/to/layer.json
```

This combines VulcansTrace detector/rule coverage with any observed agent posture findings and log analysis findings into a single Navigator-compatible layer. The output path may be a simple filename or a path with directories; when directories are present, they are created automatically.

Exit codes:
- `0` — success, no critical findings.
- `1` — error.
- `2` — success with critical findings.
- `3` — auto-fix executed but some remediation commands failed.

### Auto-Fix (Batch Remediation)

The CLI can automatically remediate findings after an audit using the same safety infrastructure as interactive remediation:

```bash
# Preview what would change without executing anything
vulcanstrace audit --intent FullAudit --auto-fix --dry-run

# Apply safe fixes with interactive confirmation
vulcanstrace audit --intent FullAudit --auto-fix

# Skip confirmation and apply immediately
vulcanstrace audit --intent FullAudit --auto-fix --yes

# Expand the safety policy to permit service restarts
vulcanstrace audit --intent FullAudit --auto-fix --yes --allow-restart

# Also permit package install/remove operations
vulcanstrace audit --intent FullAudit --auto-fix --yes --allow-packages
```

**Safety model:**
- Commands are classified by safety impact (`ReadOnly`, `ConfigChange`, `ServiceRestart`, `PackageInstall`, `Destructive`, `Unknown`).
- The default policy permits `ReadOnly` verification and `ConfigChange` commands only.
- `--allow-restart` expands the policy to include service restarts.
- `--allow-packages` expands the policy to include package installs/removals.
- Destructive and unclassified commands are never executed automatically.
- Sections lacking explicit rollback guidance are skipped.
- Backup commands run before apply commands; if a backup fails, apply is aborted.
- If an apply command fails, rollback commands for that section are executed automatically to restore consistency.
- `--dry-run` builds and previews the full remediation plan without making any system changes. The dry-run output includes risk before/after, command count, rollback availability, restart impact, and lockout risk for each section.
- The audit exit code (`2` for critical findings) is preserved even when auto-fix succeeds; `3` is returned only when auto-fix itself fails.

## Notifications

When a scheduled audit produces new critical findings, a notification is sent through the configured channel. Notification failures are logged to `stderr` and do not affect the audit exit code.

### Drift-Alert Notifications

When a schedule has **autonomous drift response** enabled, drift at or above the configured severity triggers a signed alert through the same notification channel. The alert payload includes:

- `title`, `message` (body)
- `scheduleId`, `scheduleName`
- `nonce` — per-alert nonce bound into the signature
- `maxSeverity`, `driftFindingCount`
- `ruleIds`, `attackChainNarratives`, `proactiveAlertSummaries`
- `remediationSummary` — human-approved remediation preview when remediation is enabled
- `timestampUtc`
- `signature` — HMAC-SHA256 hex, or `UNSIGNED` when no signing key is configured

Configure signing with:

```bash
export VT_ALERT_SIGNING_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
export VT_REQUIRE_SIGNED_ALERTS=1   # optional: skip unsigned alerts instead of sending UNSIGNED
```

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

The webhook receives a JSON POST with the drift-alert fields above (for drift alerts) or `title`, `message`, `scheduleName`, `criticalCount`, and `timestamp` (for critical-findings notifications). Failed requests are retried up to 3 times with exponential backoff for transient errors (5xx, timeouts, connection failures).

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
- `incident-story.md` — flowing incident narrative when findings are present (matches the Incident Story tab)
- `trace-map.md` — technical edge-list Markdown of correlated findings with per-edge narratives and CIS mappings, when edges exist
- `trace-map.json` — Cytoscape.js-compatible JSON graph of findings and correlation edges, when edges exist
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
- Each detector category has a noise budget of 100 representative findings (`MaxFindingsPerDetector`). Findings are grouped by a semantic key before the budget is applied: rule-backed findings use rule ID, category, source host, and short description, while detector findings without a rule ID also include details so distinct C2 intervals stay separate. The cap limits group count rather than raw findings. If a category exceeds the budget, a warning is emitted showing how many raw findings were grouped into how many representatives. Security Agent audits use the same grouping metadata in the Avalonia chat, findings grid, history, drift, and exports.
- Some detectors may also emit warnings when individual analysis windows are truncated (for example, port scan event caps).

## Live Stream

The Avalonia UI includes a **Live Stream** tab for real-time kernel telemetry analysis.

1. Open the **Live Stream** tab.
2. Select a source:
   - **Demo scenarios** — no privileges required; choose from C2 Beaconing, SSH Brute Force, Privilege Escalation, or Random Mix. Duration auto-adjusts per scenario (C2 Beaconing defaults to 150 s; others to 60 s). Named scenarios isolate synthetic traffic so completed evidence reflects the selected scenario.
   - **Kernel Packet Capture** — requires root or `CAP_NET_RAW`; captures IPv4 TCP/UDP via `AF_PACKET`.
   - **NFLOG Netlink** — requires root or `CAP_NET_ADMIN`; reads structured events from netfilter NFLOG.
3. Select an analysis intensity.
4. Click **Start**.
5. Watch live metrics (events/sec, window size, analysis runs, delta findings).
6. New findings appear in the live grid and are added to the main findings grid.
7. Click **Stop** for graceful async shutdown.

### Demo Scenarios (CLI)

Run safe attack replay scenarios from the command line:

```bash
# List available scenarios
vulcanstrace demo list

# Run a scenario
vulcanstrace demo run --scenario c2-beaconing --duration 150 --intensity High --seed 42

# Export evidence
vulcanstrace demo run --scenario ssh-bruteforce --output-evidence demo.zip
```

Demo runs return exit code `0` when the scenario completes successfully, even when detections are produced. Export/path errors still return a non-zero code.

### NFLOG Setup

If using the NFLOG source, create a logging rule first:

```bash
sudo iptables -A INPUT -j NFLOG --nflog-group 1
```

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
