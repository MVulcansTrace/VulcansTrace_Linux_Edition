# Design Decisions: Runtime Process Threat Hunting

> The scanner and rules were designed for production safety, forensic accuracy, and deterministic behavior on live Linux systems. Every decision favors explicit signals over silent assumptions.

---

## Decision 1 — Bounded Concurrency via SemaphoreSlim(50)

**Decision:** A `SemaphoreSlim(50, 50)` limits the number of concurrent process reads.

**Rationale:** Reading `/proc` for every process involves `readlink` syscalls and file I/O. On a system with thousands of processes, unbounded concurrency would create a thundering herd of filesystem operations. Fifty concurrent tasks provide parallelism without overwhelming the VFS layer.

**Security Rationale:** The scanner must not degrade system performance while inspecting it. A fork-bomb pattern from unbounded async reads would be ironic for a security tool.

**Business Value:** Safe to run on production systems under load. The semaphore is released in exception paths so tasks never leak.

---

## Decision 2 — No PID Count Cap

**Decision:** All processes are scanned. There is no maximum PID count or early-exit threshold.

**Rationale:** A cap would create an evasion vector — an attacker could spawn filler processes to push their malicious process beyond the cap. Memory is bounded per-process via buffer limits, not by dropping processes.

**Security Rationale:** Evasion by volume is a real technique. Scanning all PIDs ensures no process is hidden by numerical flooding.

**Business Value:** Complete coverage regardless of process count. The only limit is the byte caps on individual files.

---

## Decision 3 — Per-File Fault Isolation

**Decision:** Each `/proc/<pid>/` file is read in its own `TryReadAsync` wrapper. An exception on one file does not drop the entire process.

**Rationale:** `/proc/<pid>/environ` is often unreadable without elevated privileges (mode 400). If the scanner failed the whole process when `environ` returned EACCES, it would lose `maps`, `cmdline`, and `status` data that are readable.

**Security Rationale:** Attackers may specifically chmod their `/proc` entries to 400 to hide environment variables. The scanner must still report what it can see.

**Business Value:** Partial data is better than no data. The scanner remains useful when run as non-root.

---

## Decision 4 — Read Loops for Procfs Files

**Decision:** `cmdline`, `environ`, and `maps` are read with `FileStream.ReadAsync` loops into bounded `MemoryStream`, not `File.ReadAllBytesAsync`.

**Rationale:** Procfs files are virtual — they do not have a fixed size on disk. `ReadAllBytesAsync` may under-read because the kernel reports a size that does not match the actual data available. A read loop continues until EOF or the byte cap.

**Security Rationale:** Partial reads would cause the rule to miss indicators at the end of the file. An attacker could craft environment variables or map entries that fall past a naive single-read boundary.

**Business Value:** Reliable reads of virtual filesystem files.

---

## Decision 5 — Peek-Read Truncation Detection

**Decision:** After reaching a byte cap, `ReadProcFileAsync` attempts one more byte. If successful, the file was larger than the cap and `truncated = true`.

**Rationale:** Simply comparing `bytes.Length == maxBytes` would falsely flag files that are exactly `maxBytes` in size. The peek read distinguishes true truncation from coincidental exact-size files.

**Security Rationale:** Forensic tools must distinguish "we looked and found nothing" from "we couldn't look at everything." An attacker could hide an `LD_PRELOAD` variable after 256 KB of junk environment variables. Without truncation signaling, the rule would silently miss it.

**Business Value:** Analysts can see `environTruncated=true` in metadata and know the Pass result may be incomplete.

---

## Decision 6 — First-Value-Wins Status Parsing with Duplicate Count

**Decision:** `ReadStatusAsync` tracks seen headers. The first occurrence of each header is used; duplicates increment `DuplicateFieldCount` rather than overwriting.

**Rationale:** In normal Linux, `/proc/<pid>/status` has exactly one of each header. If duplicates appear (tampered procfs, container mount, malformed test fixture), last-value-wins would silently accept the attacker's injected value.

**Security Rationale:** First-value-wins is safer than last-value-wins because appending to a file is easier than prepending. The duplicate count makes tampering detectable.

**Business Value:** Hardens the parser against malicious input without adding runtime cost.

---

## Decision 7 — Exact-Match Parent Names (Not Contains)

**Decision:** PROC-005 uses exact match (`parentLower is "apache2" or "nginx"`) and `StartsWith("httpd", Ordinal)` rather than `Contains`.

**Rationale:** `parentName.Contains("apache")` would match `apachectl` (a legitimate Apache control utility) and produce false positives. Exact match and prefix checks are precise.

**Security Rationale:** False positives erode analyst trust. A rule that fires on legitimate infrastructure tools will be ignored or disabled.

**Business Value:** Lower false-positive rate means higher confidence in true positives.

---

## Decision 8 — Versioned Interpreter Detection

**Decision:** `IsInterpreter` checks digit prefixes (`python3.11`, `php8.1`, `ruby3.2`, `perl5.34`) instead of maintaining an exhaustive name list.

**Rationale:** New interpreter versions are released regularly. A hardcoded list would require code changes for every new Ubuntu LTS.

**Security Rationale:** Attackers will use whatever interpreter is installed. Missing `python3.12` because the rule only knows `python3.11` would be a detection gap.

**Business Value:** Forward-compatible without code changes.

---

## Decision 9 — Missing-Parent Tracking in PROC-005

**Decision:** PROC-005 counts processes whose `Ppid` is not in the snapshot and surfaces `missingParentCount` and `totalChecked` in metadata on both Pass and Fail.

**Rationale:** A bare `continue` on missing parents would hide how many processes had invisible lineage. A machine with 90% orphaned PPIDs looks identical to one with 0%.

**Security Rationale:** Attackers use daemonize-and-die to orphan their children. Heavy orphaning is itself a signal of process churn or namespace boundaries.

**Business Value:** Forensic visibility into snapshot completeness. Downstream automation can threshold on `missingParentCount / totalChecked`.

---

## Summary

| Decision | Trade-off | Benefit |
|---|---|---|
| SemaphoreSlim(50) | Limits peak parallelism | Safe on production systems, no thundering herd |
| No PID cap | Higher memory use on extreme process counts | No evasion by numerical flooding |
| Per-file fault isolation | Some processes have incomplete data | Partial evidence is better than total loss |
| Read loops | More code than `ReadAllBytesAsync` | Reliable reads of virtual procfs files |
| Peek-read truncation | Requires an extra async read at cap boundary | Distinguishes true truncation from exact-size files |
| First-value-wins + duplicate count | Slightly more state in parser | Tamper detection without silent overwrites |
| Exact-match parents | Requires updating the list for new services | Eliminates false positives from substring matches |
| Versioned interpreter detection | Slightly more complex than hardcoded list | Forward-compatible with new distro releases |
| Missing-parent tracking | Adds two counters to PROC-005 | Surfaces snapshot incompleteness for forensic analysis |

---

## Security Takeaways

1. Every design decision prioritizes forensic accuracy over convenience
2. Silent truncation and silent overwrites are treated as bugs, not optimizations
3. Production safety (bounded concurrency, no PID cap, fault isolation) is non-negotiable
4. Exact-match and prefix checks keep false-positive rates low enough for operational use
5. Forward-compatible interpreter detection prevents detection gaps on newer distributions