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

The panel also includes quick-action buttons for common audits, selected-finding explanation, exporting the latest agent audit through the shared evidence ZIP workflow, exporting a review-only remediation plan, and comparing either the latest two audits or two selected history entries. Remediation exports include preconditions, backup commands, apply commands, rollback commands or hints, and verification commands; risky or unclassified apply/backup commands must have explicit rollback guidance before the plan can be exported. Audit comparisons open with a deterministic narrative summary of what changed before the detailed counts and match findings by stable fingerprint, with rule-ID/target fallback for older history entries. Audit history is persisted when possible and keeps the latest 50 lightweight snapshots by default. Agent audit findings are loaded into the main findings grid, where they can be selected for explanation or marked as accepted risk. The Coverage tab shows passed, active failed, suppressed, and crashed rule checks by category after an agent audit. The chat shows a data-source capability report for local scanner inputs such as iptables, nftables, ss, netstat, ip, and systemctl, including permission-limited sources. Accepted-risk suppressions are fingerprint-scoped when possible and can be set for 7, 30, or 90 days, or permanently; expired suppressions stop applying immediately, remain visible in the suppression review queue for 30 days, and are then pruned during audits. Legacy suppressions without fingerprints still match by rule ID and target. Suppressions are persisted when possible; if persistence is unavailable, the UI reports that suppressions are session-only.

The right-side Suppressions tab shows entries needing review, including items expiring soon, recently expired suppressions, permanent suppressions, and stale permanent suppressions. From that queue you can renew, convert duration, edit the reason, or remove the suppression.

Agent chat findings can be filtered by severity and category without changing the underlying audit result. Copyable verification commands include safety badges such as ReadOnly, ConfigChange, ServiceRestart, PackageInstall, Destructive, or Unknown, plus inline SUDO, CHAIN, PIPE, REDIR, and DL-EXEC badges when those command structures are detected.

The agent reads local host state through Linux tools such as `iptables`, `nft`, `ss`, `netstat`, `systemctl`, and `ip`. It reports scanner permission or availability issues as warnings and as a capability report that is also included in Markdown and HTML evidence exports. The main log input is shared with the agent, so pasted firewall logs can be included when the agent runs log analysis.

For the full capability list and limitations, see [Security Agent](SECURITY_AGENT.md).

## Rule Tuning / Local Policy

The agent supports per-machine-role rule tuning via a local policy file. The desktop UI currently runs the agent as **Workstation**; the other roles are available through the agent API and policy provider wiring until a role selector is added. Roles are:

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
