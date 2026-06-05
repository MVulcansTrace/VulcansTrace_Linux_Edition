# Evasion and Limitations: Runtime Process Threat Hunting

## Known Limitations

| Limitation | Impact | Severity |
|---|---|---|
| Procfs race conditions | A process may exit between enumeration and file read, producing stale or null data | Medium |
| PID reuse | A PID may be recycled between snapshot and rule evaluation, causing parent-child mismatches | Low |
| Namespace boundaries | Processes in other PID namespaces (containers, LXC, systemd-nspawn) are invisible | High |
| Thread-level inspection gap | Injection into individual threads of a multi-threaded process does not surface distinct maps | Medium |
| Byte caps | Files exceeding 64 KB (cmdline), 256 KB (environ), or 512 KB (maps) are truncated | Medium |
| Parent exit evasion | An attacker can exit their parent quickly (daemonize-and-die); PROC-005 tracks missing parents but does not flag it as a violation | Medium |
| No cross-process correlation | Each process is evaluated independently; multi-process attack chains are not correlated | Medium |
| Interpreter list coverage | `IsInterpreter` covers common interpreters but may miss niche or custom ones | Low |
| cmdline null-byte replacement | Null bytes are replaced with spaces, which can obscure argument boundaries | Low |
| Non-root visibility | `/proc/<pid>/environ` and `/proc/<pid>/maps` may be unreadable without elevated privileges | Medium |
| Deleted binary path ambiguity | A legitimate update-in-place can produce `(deleted)` on a benign binary | Low |

---

### Procfs Race Conditions

The scanner enumerates PIDs, then reads files. Between these two moments, a process can exit. The kernel removes `/proc/<pid>/` immediately on process death. `File.Exists` checks and `FileStream` opens can fail with `ENOENT`.

**Mitigation:** `TryReadAsync` catches these exceptions and returns null/defaults. The scanner continues with other processes. This is expected behavior on a live system.

**Improvement options:** None — this is inherent to reading live kernel state. Faster scanning reduces the race window.

---

### PID Reuse

Linux recycles PIDs aggressively. If process A (PID 100) exits and process B (PID 100) starts between snapshot and rule evaluation, PROC-005 could incorrectly pair B with A's parent.

**Mitigation:** The scanner reads all files within a single `ReadProcessAsync` call, minimizing the time window. Rules evaluate the snapshot immediately after it is built. In practice, PID reuse within milliseconds is rare on typical systems.

**Improvement options:** Add PID start-time validation via `/proc/<pid>/stat` field 22 (`starttime`). This would require parsing the complex `stat` format and is deferred.

---

### Namespace Boundaries

`ProcessRuntimeScanner` reads the host `/proc`. Processes inside containers with separate PID namespaces are invisible unless the scanner runs inside the container.

**Mitigation:** This is documented as a known limitation. Container rules (CTR-001..005) and Kubernetes rules (K8S-001..004) cover container-specific posture.

**Improvement options:** Add namespace-aware scanning by reading `/proc/<pid>/ns/pid` and iterating container PID namespaces. This requires elevated privileges and complex namespace switching.

---

### Thread-Level Inspection Gap

The scanner reads `/proc/<pid>/maps` at the process level. If a multi-threaded process has a malicious thread with distinct RWX mappings, those maps are visible in the process-level `maps` file (Linux merges thread maps into the process file). However, injection that targets only a specific thread's memory via `ptrace` or `process_vm_writev` would not create distinct `/proc/<pid>/maps` entries.

**Mitigation:** PROC-001 still detects RWX regions at the process level, which most injection techniques create.

**Improvement options:** Thread-level inspection via `/proc/<pid>/task/<tid>/maps` would add significant complexity and is not currently planned.

---

### Byte Caps and Truncation

An attacker can evade PROC-002 by stuffing 260 KB of junk environment variables before the real `LD_PRELOAD` variable. The scanner stops at 256 KB and returns `EnvironTruncated = true`, but the rule only sees the visible portion.

**Mitigation:** Truncation metadata (`environTruncated`) is surfaced in rule results. On Pass, the metadata tells analysts the data was incomplete. An analyst seeing `environTruncated=true` on an otherwise clean scan should investigate further.

**Improvement options:** Increase caps (memory trade-off), or add a dedicated "truncated evidence" finding when truncation occurs on processes with suspicious characteristics.

---

### Parent Exit Evasion

An attacker can fork twice and exit the intermediate parent, leaving the child orphaned under `init`. PROC-005 would see the child with `Ppid=1` and not find the original parent.

**Mitigation:** PROC-004 detects orphaned processes with anomalous names. PROC-005 tracks `missingParentCount` so analysts can see heavy orphaning. The two rules together provide coverage.

**Improvement options:** Historical parent tracking (impossible without kernel auditd rules). Long-term process-tree reconstruction from repeated snapshots.

---

### No Cross-Process Correlation

Each rule evaluates individual processes. A multi-process attack (e.g., one process drops the payload, another executes it, a third injects) is not correlated into a single finding.

**Mitigation:** This is consistent with other agent rules, which also evaluate individual records. The `RiskEscalator` in the engine correlates findings across categories.

**Improvement options:** Add a `ProcessRuntimeCorrelator` that links findings by PPID chains, shared environment variables, or temporal proximity.

---

### Non-Root Visibility

Without elevated privileges, `/proc/<pid>/environ` is often mode 400 (readable only by owner). This limits PROC-002 coverage for processes owned by other users.

**Mitigation:** The scanner reports `PermissionLimited` capability status. Rules still evaluate available data. Running with elevated privileges provides full coverage.

---

## Improvement Roadmap

| Improvement | Description | Priority |
|---|---|---|
| Namespace-aware scanning | Read container PID namespaces for cross-namespace visibility | Low |
| Thread-level maps inspection | Check `/proc/<pid>/task/<tid>/maps` for per-thread injection signals | Low |
| Increased byte caps | Raise cmdline/environ/maps caps for deep forensic scans | Medium |
| Cross-process correlation | Link related process findings by PPID chains or shared env vars | Medium |
| Process-tree visualization | Build and display a full PPID tree with anomaly highlighting | Medium |
| Historical snapshot comparison | Compare process lists across audits to detect new/deleted/changed processes | High |
| Start-time validation | Parse `/proc/<pid>/stat` starttime to guard against PID reuse | Low |
| Additional interpreters | Expand `IsInterpreter` for niche languages (lua, node, ruby variants) | Low |

---

## Security Takeaways

1. The scanner is most effective against in-memory threats that leave no configuration traces
2. Race conditions are inherent to live kernel inspection and are handled gracefully, not eliminated
3. Namespace boundaries are the biggest coverage gap; container-specific rules provide complementary coverage
4. Truncation metadata prevents silent false negatives from byte-cap evasion
5. Missing-parent tracking surfaces daemonize-and-die techniques even when they evade direct parent-child detection
6. The improvement roadmap prioritizes historical snapshot comparison, which would turn point-in-time inspection into continuous process monitoring