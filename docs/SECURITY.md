# Security

OFFLINE POLICY: This app is 100% offline. It does not send logs, telemetry, or analytics anywhere.

## Data Handling

- Logs are processed locally in memory.
- Evidence bundles are written only to user-selected files.
- No telemetry or remote logging is built into the app.

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
- Atomic file writes (temp file + move) are used for all JSON persistence to prevent corruption on power loss.

## Notifications

Notifications are sent only when **new** critical findings are detected, using fingerprint-aware diffing against previous audit history. This prevents alert fatigue and reduces notification surface area.

- **Desktop notifications** use the local `notify-send` command. No network calls.
- **Email notifications** use user-configured SMTP settings via environment variables. No third-party email APIs.
- **Webhook notifications** POST to a user-configured URL. No telemetry or analytics payloads are included.

All notification failures are caught and logged to `stderr`; they do not affect audit execution or exit codes.

## Persistence

Sensitive data is stored in the user's config directory (`~/.config/VulcansTrace/`):
- `schedules.json` — recurring audit schedules.
- `audithistory.json` — lightweight audit history snapshots.
- `baselines.json` — configuration baselines.
- `policy.json` — local rule policy overrides.
- `suppressions.json` — accepted-risk suppressions.

These files contain posture findings and local configuration only. No logs, telemetry, or external data is stored.
