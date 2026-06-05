> **1 page:** the Runtime Process Threat Hunting subsystem, why it matters, and where the proof lives in the codebase.

---

## Implementation Overview

The Runtime Process Threat Hunting subsystem adds a live-process DFIR path to the VulcansTrace Security Agent. `ProcessRuntimeScanner` enumerates every numeric directory in `/proc/`, reads six files per process (`status`, `comm`, `exe`, `cmdline`, `maps`, `environ`) with a concurrency limit of 50, and populates `ProcessRuntimeEntry` records. Six rules evaluate the snapshot for injection, persistence, anti-forensics, interpreter payload execution, and anomalous relationships.

This is not a configuration audit — it inspects the running state of the kernel's process table, making it complementary to static posture checks.

---

## Key Metrics

| Metric | Value |
|---|---|
| Scanner | `ProcessRuntimeScanner` |
| Data source | `/proc/<pid>/status`, `/proc/<pid>/comm`, `/proc/<pid>/exe`, `/proc/<pid>/cmdline`, `/proc/<pid>/maps`, `/proc/<pid>/environ` |
| Concurrency limit | 50 (`SemaphoreSlim`) |
| Rule count | 6 (PROC-001..006) |
| Rule category | `FindingCategories.ProcessRuntime` |
| Agent intent | `ProcessRuntimeCheck` |
| Cmdline cap | 64 KB |
| Environ cap | 256 KB |
| Maps cap | 512 KB |
| Cancellation points | Per-directory enumeration, per-process `ReadProcessAsync`, per-file `ReadProcFileAsync` |
| Test coverage | 50+ unit tests covering scanner parsing, rule pass/fail/NotApplicable, metadata contracts, unreadable-evidence semantics |
| MITRE mappings | T1055, T1620, T1574.006, T1036, T1105, T1059 |

---

## Why It Matters

- **Configuration audits miss live compromise** — a backdoor already running in memory will not appear in SSH config files or cron tables
- **RWX memory is a direct injection signal** — MITRE T1055 (Process Injection) and T1620 (Reflective Code Loading) both manifest as executable writable regions
- **Interpreter RWX is a high-signal runtime anomaly** — python/perl/ruby/php processes with RWX maps can indicate `-c` payloads, eval loaders, shellcode staging, or native-extension abuse
- **LD_PRELOAD is a common Linux persistence technique** — MITRE T1574.006 (Dynamic Linker Hijacking) hides in environment variables invisible to file-based scanners
- **Deleted binaries are classic anti-forensics** — MITRE T1036 (Masquerading) and T1105 (Ingress Tool Transfer) both use execution from `/tmp` or `(deleted)` paths
- **Parent-child anomalies expose RCE** — a web server spawning `bash` or `python3` is often the first observable signal of successful exploitation
- **Bounded concurrency + per-file isolation** — the scanner remains safe on heavily loaded systems and does not crash when individual `/proc` files are unreadable

---

## Key Evidence

- [ProcessRuntimeScanner.cs](../../../../VulcansTrace.Linux.Agent/Scanners/ProcessRuntimeScanner.cs) — scanner implementation
- [ProcessRuntimeEntry.cs](../../../../VulcansTrace.Linux.Agent/Scanners/ProcessRuntimeEntry.cs) — snapshot record with truncation flags and duplicate-field count
- [ProcessRuntimeRules.cs](../../../../VulcansTrace.Linux.Agent/Rules/SecurityRules/ProcessRuntimeRules.cs) — six rule implementations and MITRE technique catalog
- [ProcessRuntimeScannerTests.cs](../../../../VulcansTrace.Linux.Tests/Agent/ProcessRuntimeScannerTests.cs) — scanner parser tests
- [ProcessRuntimeRulesTests.cs](../../../../VulcansTrace.Linux.Tests/Agent/ProcessRuntimeRulesTests.cs) — rule behavior tests

---

## Key Design Choices

- **SemaphoreSlim(50)** — bounds concurrent `readlink` and procfs reads to avoid fork-bombing the system; releases are guaranteed in `finally`-equivalent catch blocks
- **No PID count cap** — all processes are scanned; memory is bounded per-process via buffer limits, not by dropping processes
- **Per-file fault isolation** — each `/proc` file read is wrapped in its own `TryReadAsync` call so EACCES on `environ` does not lose the entire process entry
- **Read loops for procfs** — `cmdline`, `environ`, and `maps` use `FileStream.ReadAsync` loops into `MemoryStream` because procfs files may return partial reads
- **Peek-read truncation detection** — after reaching a byte cap, `ReadProcFileAsync` attempts one more byte; success means the file was truncated, and the flag flows through to rule metadata
- **Unreadable-evidence flags** — process entries preserve whether maps, environ, cmdline, and exe resolution were readable, so rules can avoid clean passes when required evidence was unavailable
- **First-value-wins status parsing** — `ReadStatusAsync` tracks seen headers; duplicates increment `DuplicateFieldCount` rather than silently overwriting, making procfs tampering detectable
- **Exact-match parent names** — PROC-005 uses `parentLower is "apache2" or "nginx"` and `StartsWith("httpd")` rather than `Contains`, eliminating `apachectl` false positives
- **Versioned interpreter detection** — `IsInterpreter` checks digit prefixes (`python3.11`, `php8.1`) so new interpreter versions do not require rule updates

---

## Security Takeaways

1. Runtime process inspection is essential for DFIR — static configuration audits cannot see memory-resident threats
2. RWX mappings are a high-confidence injection signal; few legitimate processes maintain RWX regions in steady state
3. LD_PRELOAD and LD_AUDIT are powerful persistence mechanisms that are invisible to file-based scanners
4. Truncation and unreadable-evidence metadata ensure analysts can distinguish "no findings" from "incomplete evidence"
5. Missing-parent tracking surfaces snapshot incompleteness that could otherwise hide daemonize-and-die evasion
6. Bounded concurrency and per-file isolation make the scanner safe to run on production systems
