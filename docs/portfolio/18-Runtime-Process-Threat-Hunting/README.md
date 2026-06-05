# Runtime Process Threat Hunting

The Runtime Process Threat Hunting subsystem scans live Linux process state from `/proc/<pid>/` and evaluates six DFIR-focused rules to detect injection, persistence, anti-forensics, interpreter payload execution, and anomalous parent-child relationships that static configuration audits cannot see.

Documentation is organized for two audiences:

- **Recruiters and hiring managers** who need a fast, high-level view of what this subsystem does and why it matters
- **Technical reviewers** who want to inspect the actual implementation choices, scanner pipeline, rule behavior, and test evidence

## Start Here

- [Technical Snapshot](./Runtime-Process-Threat-Hunting-Summary/Technical-Snapshot.md) — one-page overview of the scanner, rules, and proof points
- [Quick Reference](./Runtime-Process-Threat-Hunting-Summary/Quick-Reference.md) — rule table, scanner caps, data fields, and metadata flags at a glance
- [Why This Matters](./Runtime-Process-Threat-Hunting-In-Depth/Why-This-Matters.md) — the security gap this feature fills and why runtime data is essential
- [Detection Algorithm](./Runtime-Process-Threat-Hunting-In-Depth/Core-Logic-Breakdown/Detection-Algorithm.md) — step-by-step walkthrough of the scanner read pipeline and rule evaluation
- [Design Decisions](./Runtime-Process-Threat-Hunting-In-Depth/Design-Decisions.md) — bounded concurrency, no PID cap, per-file fault isolation, read loops, truncation flags, and missing-parent tracking
- [Code Patterns](./Runtime-Process-Threat-Hunting-In-Depth/Code-Patterns.md) — `TryReadAsync` wrapper, bounded `MemoryStream`, value-tuple returns, and enumeration patterns
- [Attack Scenario](./Runtime-Process-Threat-Hunting-In-Depth/Attack-Scenario.md) — worked example showing multi-rule detection of a live compromise
- [Evasion and Limitations](./Runtime-Process-Threat-Hunting-In-Depth/Evasion-and-Limitations.md) — known weaknesses and the improvement roadmap
- [MITRE ATT&CK Mapping](./Runtime-Process-Threat-Hunting-In-Depth/MITRE-ATTACK-Mapping.md) — technique mapping and attack lifecycle context

## System Capabilities

- **Live /proc scanning** — reads `status`, `comm`, `exe` (via `readlink`), `cmdline`, `maps`, and `environ` for every running process with bounded concurrency (`SemaphoreSlim(50)`)
- **Per-file fault isolation** — EACCES or other errors on one `/proc/<pid>/` file do not drop the entire process; the scanner continues with available data
- **Read-loop hardening** — `cmdline`, `environ`, and `maps` are read into bounded `MemoryStream` with byte caps to handle partial procfs reads safely
- **Truncation signaling** — when a file exceeds its cap (64 KB cmdline, 256 KB environ, 512 KB maps), a `Truncated` flag is returned and surfaced in rule metadata so analysts know evidence may be incomplete
- **Duplicate-field guard** — `/proc/<pid>/status` parser tracks seen headers and counts duplicates, surfacing the count on `ProcessRuntimeEntry` as a tamper-detection signal
- **Missing-parent visibility** — PROC-005 tracks how many processes had parents not present in the snapshot, surfacing the count in metadata even when no violations are found
- **Six DFIR rules**:
  - **PROC-001** (Critical) — RWX memory mappings indicating process injection or shellcode
  - **PROC-002** (High) — `LD_PRELOAD` / `LD_AUDIT` dynamic linker hijacking
  - **PROC-003** (High) — execution from deleted binaries or temporary paths (`/tmp`, `/var/tmp`, `/dev/shm`)
  - **PROC-004** (Medium) — orphaned processes with anomalous names running under init (PPid=1)
  - **PROC-005** (High) — suspicious parent-child relationships (web servers spawning shells, SSH spawning interpreters, databases spawning shells, cron spawning network tools)
  - **PROC-006** (Critical) — interpreter processes with RWX mappings, highlighting in-memory payload execution in python, perl, ruby, and php
- **Unreadable-evidence signaling** — evidence-specific rules distinguish unreadable `/proc` files from empty files, returning NotApplicable when required evidence is entirely unreadable and surfacing unreadable-count metadata for partial visibility
- **Versioned interpreter detection** — rules detect `python3.11`, `php8.1`, `ruby3.2`, `perl5.34` via digit-prefix checks, not brittle exact-name lists
- **Exact-match parent names** — PROC-005 uses exact match and `StartsWith` (not `Contains`) to avoid false positives such as `apachectl` matching `apache2`
- **Cancellation-safe** — cooperative cancellation with `ThrowIfCancellationRequested`; cancellation is re-thrown so the orchestrator can distinguish cancel from empty `/proc`
- **Deterministic tests** — 50+ tests covering `ParseMapLine`, `IsAnomalousName`, `IsSuspiciousPair`, and all six rules across pass/fail/NotApplicable paths

## Implementation Evidence

- [ProcessRuntimeScanner.cs](../../../VulcansTrace.Linux.Agent/Scanners/ProcessRuntimeScanner.cs) — live /proc scanner with bounded concurrency, read loops, truncation detection, and duplicate-field guards
- [ProcessRuntimeEntry.cs](../../../VulcansTrace.Linux.Agent/Scanners/ProcessRuntimeEntry.cs) — process snapshot record with truncation flags and duplicate-field count
- [ProcessRuntimeRules.cs](../../../VulcansTrace.Linux.Agent/Rules/SecurityRules/ProcessRuntimeRules.cs) — six PROC rules: RWX maps, LD_PRELOAD injection, deleted binaries, orphaned anomalous processes, suspicious parent-child pairs, and interpreter RWX
- [ProcessRuntimeScannerTests.cs](../../../VulcansTrace.Linux.Tests/Agent/ProcessRuntimeScannerTests.cs) — scanner tests: ParseMapLine validation, address range guards, permission guards, path-with-spaces handling
- [ProcessRuntimeRulesTests.cs](../../../VulcansTrace.Linux.Tests/Agent/ProcessRuntimeRulesTests.cs) — rule tests: all six rules across pass/fail/NotApplicable, missing parent metadata, unreadable-evidence semantics, anomalous name detection, suspicious pair matrix
- [processruntime.md](../../../VulcansTrace.Linux.Agent/Explanations/Templates/processruntime.md) — markdown explanation template for all six rules
