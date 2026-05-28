# Architecture

VulcansTrace Linux Edition is structured as layered projects that keep parsing, detection, UI, and evidence packaging isolated. The result is a local-only analysis pipeline that can be reused by UI and CLI tools.

## System Overview

- `VulcansTrace.Linux.Core`: domain models and log parsing (UnifiedEvent, LogNormalizer).
- `VulcansTrace.Linux.Engine`: detectors, profiles, and analysis orchestration.
- `VulcansTrace.Linux.Evidence`: evidence bundle creation and report formatting.
- `VulcansTrace.Linux.Avalonia`: Avalonia UI and composition root.
- `VulcansTrace.Linux.Tests`: unit and integration tests.
- `VulcansTrace.Linux.Performance`: performance benchmarks and metrics.
- `VulcansTrace.Linux.PerformanceConsole`: console runner for performance tests.
- `tools/TestAnalysis`: sample CLI analysis runner (not part of the solution file).

## Data Flow

1. Raw firewall log text is provided by the UI or a tool.
2. `LogNormalizer` detects iptables vs nftables and produces `UnifiedEvent` entries.
3. `SentryAnalyzer` runs three detector layers:
   - Baseline detectors (ported from Windows logic).
   - Linux Deep Inspection detectors (Linux-specific signals).
   - Advanced threat detectors (C2 channels, privilege escalation).
4. `RiskEscalator` increases severity when correlated signals are present.
5. Overlapping Beaconing and C2Channel findings on the same source-destination tuple are deduplicated (C2Channel absorbs the Beaconing details).
6. Findings are filtered by the profile's minimum severity (`MinSeverityToShow`) and per-category cap (`MaxFindingsPerDetector`).
7. `AnalysisResult` is returned with findings, warnings, parse errors, and time range metadata.
8. The UI renders findings, and `EvidenceBuilder` optionally creates a signed bundle.

## Key Domain Types

- `UnifiedEvent`: normalized schema for firewall logs, including Linux-specific fields.
- `AnalysisProfile`: intensity-tuned thresholds for each detector.
- `Finding`: immutable detector output with severity and time range.
- `AnalysisResult`: complete analysis output with entries, findings, and warnings.

## Detection Layers

Baseline detectors:
- PortScan, Flood, LateralMovement, Beaconing, PolicyViolation, Novelty.

Linux Deep Inspection detectors:
- FlagAnomaly, MacSpoofing, KernelModule, InterfaceHopping, UnusualPacketSize.

Advanced threat detectors:
- C2Channel, PrivilegeEscalation.

Risk escalation correlations include (when both findings occur within a correlated 24-hour window):
- Beaconing + LateralMovement -> Critical.
- FlagAnomaly + PortScan -> Critical.
- MacSpoofing + InterfaceHopping -> Critical.

## Logging

Runtime logging is abstracted behind `ILogSink`. The UI uses `DiagnosticsLogSink` to emit to `System.Diagnostics.Trace`, while parsers and engine default to `NullLogSink` if no sink is provided.
