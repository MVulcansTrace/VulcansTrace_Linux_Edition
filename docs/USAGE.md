# Usage

## Avalonia UI

1. Launch the app with `dotnet run --project VulcansTrace.Linux.Avalonia`.
2. Paste iptables or nftables log text into the main input area.
3. Select a scan intensity:
   - **Low - Critical Threat Triage** — conservative thresholds, fewer findings.
   - **Medium - Investigation Review** — balanced thresholds for standard investigations.
   - **High - Deep Hunt / Forensics** — aggressive thresholds for deep hunts and forensics.
4. Click **Analyze** to generate findings.
5. Review results:
   - **Findings tab** — searchable, filterable table of all detected threats. Use the search box and severity dropdown to narrow results.
   - **Timeline tab** — visual timeline of findings by category.
   - **Parse Errors tab** — lines that could not be parsed.
   - **Warnings tab** — analysis notices (truncation, caps, etc.).
6. Use **Export Evidence** to save a cryptographically-signed ZIP bundle.

### Security Agent Panel

The Avalonia UI also includes a collapsible **Security Agent** panel. It can answer local posture questions such as:

- `Is my system secure?`
- `Check my firewall`
- `What ports are open?`
- `What services are running?`
- `Who am I talking to?`
- `Explain FW-001`

The panel also includes quick-action buttons for common audits, selected-finding explanation, and exporting the latest agent audit through the shared evidence ZIP workflow. The agent reads local host state through Linux tools such as `iptables`, `nft`, `ss`, `netstat`, `systemctl`, and `ip`. It reports scanner permission or availability issues as warnings. The main log input is shared with the agent, so pasted firewall logs can be included when the agent runs log analysis.

For the full capability list and limitations, see [Security Agent](SECURITY_AGENT.md).

## Evidence Export

Exporting evidence produces a ZIP archive with:
- `findings.csv`
- `findings.json`
- `findings.stix.json`
- `report.html`
- `summary.md`
- `log.txt`
- `manifest.json` — file hashes, skipped line count, and parse error details
- `manifest.hmac` — HMAC-SHA256 signature for integrity verification

The signing key is generated per analysis session and masked in the UI. Re-running analysis creates a new key; repeated exports of the same result reuse the session key. Copy and store it if you need to verify the bundle later.

Bundles can be verified end-to-end using the built-in Verify API, which checks the HMAC signature and recomputes SHA-256 hashes for every file in the manifest.

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
