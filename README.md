OFFLINE POLICY: This app is 100% offline. It does not send logs, telemetry, or analytics anywhere.

# VulcansTrace Linux Edition

VulcansTrace Linux Edition is a desktop forensic analyzer for Linux firewall logs (iptables and nftables). It normalizes raw logs into a unified schema, runs layered detectors, and produces signed evidence bundles for incident response, while being 100% offline.

## Highlights

- Local-first analysis with no network dependency.
- UnifiedEvent normalization for iptables and nftables logs.
- Baseline detectors: PortScan, Flood, LateralMovement, Beaconing, PolicyViolation, Novelty.
- Linux Deep Inspection detectors: FlagAnomaly, MacSpoofing, KernelModule, InterfaceHopping, UnusualPacketSize.
- Advanced detectors: C2Channel and PrivilegeEscalation (admin access spike and admin port sweep detection).
- Correlated risk escalation (e.g., Beaconing + LateralMovement).
- Evidence bundle export with CSV, HTML, Markdown, JSON, STIX, and HMAC manifest signing.

## Supported Log Formats

- iptables kernel logs (`/var/log/kern.log`-style prefixes).
- nftables kernel logs (`nf_tables:` entries).

## Quick Start

Prerequisites:
- .NET 9.0 SDK

Build and run:
```bash
dotnet build
dotnet run --project VulcansTrace.Linux.Avalonia
```

Run tests:
```bash
dotnet test
```

Optional CLI test tool:
```bash
dotnet run --project tools/TestAnalysis -- VulcansTrace.Linux.Tests/Data/Real/Samples/iptables-attack.log
```

## Evidence Bundles

The UI can export a signed ZIP evidence package containing:
- `findings.csv`
- `findings.json`
- `findings.stix.json`
- `report.html`
- `summary.md`
- `log.txt`
- `manifest.json` and `manifest.hmac` (HMAC-SHA256)

The signing key is generated for each analysis session and shown in the UI (masked by default). Re-running analysis creates a new key; repeated exports of the same result use the same key. Store it securely to verify integrity later.
See `docs/HMAC_EVIDENCE.md` for the step-by-step HMAC signing key flow.

## Configuration and Limits

- Restore uses `nuget.config` pointing to the public nuget.org feed.
- Logs are capped at 100,000,000 characters to prevent memory exhaustion.
- Parse errors retained in analysis results are capped at 500.
- Intensity profiles tune detector thresholds (Low, Medium, High).

## Documentation

- Architecture: `docs/ARCHITECTURE.md`
- Usage: `docs/USAGE.md`
- Development: `docs/DEVELOPMENT.md`
- Security and offline policy: `docs/SECURITY.md`
- Audit reports: `docs/portfolio/` (15 implementation portfolios covering detection algorithms, UI architecture, test coverage, and design decisions)

## Offline and Security

The application itself never makes network calls. An optional internal vulnerability scan exists for build pipelines:
`scripts/internal-security-scan.sh` (requires `VULCANSTRACE_INTERNAL_VULN_API` and `VULCANSTRACE_INTERNAL_VULN_TOKEN`).
