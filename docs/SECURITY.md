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

## Optional Internal Vulnerability Scan

Build pipelines can invoke `scripts/internal-security-scan.sh` to upload dependency lists to an internal scanner. This script is not called by the application and only runs when explicitly executed with:
- `VULCANSTRACE_INTERNAL_VULN_API`
- `VULCANSTRACE_INTERNAL_VULN_TOKEN`

## Defensive Parsing

- iptables and nftables parsers require SRC/DST/PROTO fields (lines missing them are skipped), validate port ranges (0–65535), and validate timestamp formats.
- Log input size is capped at 100,000,000 characters to reduce memory exhaustion risk.
