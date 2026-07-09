# Security

OFFLINE POLICY: This app does not send logs, telemetry, or analytics anywhere. Most analysis is local-only; optional user-configured integrations such as SMTP/webhook notifications and Kubernetes scans may contact the endpoints the user configured.

## Data Handling

- Logs are processed locally in memory.
- Evidence bundles are written only to user-selected files.
- No telemetry or remote logging is built into the app.
- Kubernetes posture checks run `kubectl` against the user's configured context when kubeconfig exists; disable or remove that context if cluster API access is not desired.

## Evidence Integrity

Evidence bundles include:
- SHA-256 hashes for each file in `manifest.json`.
- HMAC-SHA256 signature in `manifest.hmac`.

The signing key is generated per analysis session and must be retained by the operator if later verification is required. Re-running analysis creates a new key; repeated exports of the same result reuse the session key.
See `docs/HMAC_EVIDENCE.md` for the step-by-step HMAC signing key flow.

## Defensive Parsing

- iptables and nftables parsers require SRC/DST/PROTO fields (lines missing them are skipped), validate port ranges (0–65535), and validate timestamp formats.
- Log input size is capped at 100,000,000 characters to reduce memory exhaustion risk.

## Scheduling and Cron Integration

Recurring audits use the standard Linux `crontab` command. VulcansTrace:
- Reads and writes the **user crontab** only (never system-wide crontabs).
- Uses a unique marker prefix (`# VT-SCH-7a3f9e2d schedule-id=`) to avoid interfering with non-VulcansTrace entries.
- Validates cron expressions before installation.
- Rejects installation of disabled schedules.
- Atomic file writes (temp file + move) are used for schedules and agent-memory persistence to prevent corruption on power loss. Other persisted JSON files are written directly; the same directory is created and validated before each save.

## Notifications

Notifications are sent only when **new** critical findings are detected, using fingerprint-aware diffing against previous audit history. This prevents alert fatigue and reduces notification surface area.

- **Desktop notifications** use the local `notify-send` command. No network calls.
- **Email notifications** use user-configured SMTP settings from `notification-settings.json`. No third-party email APIs. The file is written with owner-only permissions on Unix because it may contain an SMTP password.
- **Webhook notifications** POST to a user-configured URL. No telemetry or analytics payloads are included.
- **Drift alerts** are sent when a scheduled audit has autonomous drift response enabled and baseline drift at or above the configured threshold is detected.

All notification failures are caught; email and webhook failures are logged to `stderr`. Desktop notification failures are silently degraded if `notify-send` is unavailable. None of these failures affect audit execution or exit codes.

## Drift Alert Signing

Autonomous drift alerts can be HMAC-SHA256 signed so recipients can verify authenticity and detect tampering.

- Set `VT_ALERT_SIGNING_KEY` to a hex-encoded key (for example, a 64-character hex string representing 32 bytes). The same key must be available to the verifier. The CLI parses any valid hex string and does not enforce a fixed length.
- Each signed alert includes a per-alert `Nonce` and the `ScheduleId` in the signed canonical JSON form.
- `SignedAlertVerifier` uses constant-time comparison (`CryptographicOperations.FixedTimeEquals`) to resist timing attacks.
- Alerts sent without a signing key carry the explicit `UNSIGNED` sentinel value so recipients cannot mistake them for authenticated alerts.
- Set `VT_REQUIRE_SIGNED_ALERTS=1` (or enable **Require signed alerts** on a schedule) to skip sending alerts when no key is configured.

The verifier guarantees integrity and origin-binding. It does not, by itself, guarantee freshness (replay resistance); recipients that need replay resistance must maintain a cache of observed nonces and reject duplicates.

## Auto-Fix and Scheduled Remediation Safety

The CLI `--auto-fix` feature and the `vulcanstrace schedule remediate` command execute shell commands derived from explanation templates. Several guardrails are in place:

- Commands are classified by safety impact before execution (`ReadOnly`, `ConfigChange`, `ServiceRestart`, `PackageInstall`, `Destructive`, `Unknown`).
- The default policy permits `ReadOnly` verification and `ConfigChange` only; `--allow-restart` and `--allow-packages` (or the schedule equivalents) expand the policy explicitly.
- Destructive and unclassified commands are never executed automatically.
- `RemediationPlanValidator` blocks sections where risky commands lack explicit rollback guidance.
- Backup commands run before apply commands; backup failures abort the section.
- If an apply command fails, rollback commands are executed automatically for that section.
- Commands are fed to bash via stdin (not `-c` argument wrapping) to prevent shell escaping vulnerabilities.
- `--dry-run` previews the full plan without executing anything.
- `--yes` skips interactive confirmation; without it, the user must type `yes` to proceed.
- Scheduled remediation applies the schedule's rule-prefix scope via `RemediationScopeFilter` before building the plan, so a schedule scoped to `FW` cannot remediate `SSH`, `KERN`, or other rule families.
- Auto-fix and scheduled remediation are client-side operations; no commands or results leave the local machine.

The Security Agent never autonomously applies remediation. Every automatic system change requires explicit operator approval.

## Persistence

Sensitive data is stored in the user's config directory (`~/.config/VulcansTrace/`):
- `schedules.json` — recurring audit schedules.
- `audit-history.json` — lightweight audit history snapshots.
- `baselines.json` — configuration baselines.
- `policy.json` — local rule policy overrides.
- `suppressions.json` — accepted-risk suppressions.

These files contain posture findings and local configuration only. No logs, telemetry, or external data is stored. The location is resolved by `VulcansTraceConfig`, which honors `--config-dir`, `XDG_CONFIG_HOME`, or the default `~/.config/VulcansTrace`.
