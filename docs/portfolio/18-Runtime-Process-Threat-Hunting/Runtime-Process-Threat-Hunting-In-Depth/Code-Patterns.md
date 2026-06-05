# Code Patterns: Runtime Process Threat Hunting

> Recurring implementation patterns in the scanner and rules, and why they support reliability and testability.

---

## Pattern 1 — TryReadAsync Wrapper

**What:** A generic async wrapper that catches non-cancellation exceptions and returns `default(T)`.

```csharp
private static async Task<T?> TryReadAsync<T>(Func<Task<T?>> readFunc, CancellationToken ct)
{
    try { return await readFunc(); }
    catch (OperationCanceledException) { throw; }
    catch { return default; }
}
```

**Why it matters:** Each `/proc/<pid>/` file read is independent. `TryReadAsync` lets the scanner attempt all six files per process without try/catch clutter in every method. Cancellation is re-thrown so the orchestrator can distinguish "cancelled" from "empty /proc."

**Trade-off:** Exceptions are swallowed silently. This is acceptable because the scanner is reading kernel virtual files — transient errors are normal and unactionable at the rule level.

**Test impact:** Rules must handle null/empty fields gracefully. Tests verify that a process with empty `MemoryMaps` still evaluates correctly (e.g., PROC-001 sees no RWX and passes).

---

## Pattern 2 — Bounded MemoryStream with Byte Caps

**What:** `ReadProcFileAsync` reads into a `MemoryStream` with a hard `maxBytes` limit, then peeks one more byte to detect truncation.

```csharp
while (totalRead < maxBytes)
{
    int toRead = Math.Min(buffer.Length, maxBytes - totalRead);
    int read = await fs.ReadAsync(buffer.AsMemory(0, toRead), ct);
    if (read == 0) break;
    ms.Write(buffer, 0, read);
    totalRead += read;
}

bool truncated = false;
if (totalRead >= maxBytes)
{
    int peek = await fs.ReadAsync(buffer.AsMemory(0, 1), ct);
    if (peek > 0) truncated = true;
}

return (ms.ToArray(), truncated);
```

**Why it matters:** Procfs files have no true on-disk size. A malicious process could present an infinite `environ` stream to exhaust memory. The cap bounds memory usage, and the peek read provides a truncation signal.

**Trade-off:** Indicators past the cap are invisible. This is mitigated by surfacing `truncated` in rule metadata.

**Test impact:** Tests cannot easily create multi-megabyte procfs files. The pattern is verified indirectly through the truncation metadata on Pass results.

---

## Pattern 3 — Value Tuple Returns for Composite Data

**What:** Read methods return value tuples combining the primary data with a metadata flag.

```csharp
private static async Task<(List<ProcessMemoryMap>? Maps, bool Truncated)> ReadMapsAsync(...)
private static async Task<(List<string>? Entries, bool Truncated)> ReadEnvironAsync(...)
private static async Task<(string? Content, bool Truncated)> ReadCmdlineAsync(...)
```

**Why it matters:** The truncation flag must flow from `ReadProcFileAsync` through the caller to `ProcessRuntimeEntry`. Value tuples keep this coupling explicit and zero-allocation.

**Trade-off:** `TryReadAsync<T>` with value tuple `T` returns the tuple itself (not `Nullable<T>`) on exception because `default((List<ProcessMemoryMap>?, bool))` is `(null, false)`. This is the desired behavior — null data, not truncated.

**Test impact:** Rules tests construct `ProcessRuntimeEntry` with explicit truncation flags to verify metadata emission.

---

## Pattern 4 — Enumeration with LINQ in Rules

**What:** Rules use `Any()`, `Count()`, and `Select()` over `IReadOnlyList<T>` collections.

```csharp
proc.MemoryMaps.Any(m => m.Permissions.Length >= 3
    && m.Permissions[0] == 'r'
    && m.Permissions[1] == 'w'
    && m.Permissions[2] == 'x')
```

**Why it matters:** `IReadOnlyList<T>` is the contract between scanner and rule. LINQ keeps rule logic declarative and testable. Explicit character checks (not `Contains`) prevent false positives from malformed permission strings.

**Trade-off:** LINQ allocations on hot paths. For process runtime rules, the collections are small (maps for a single process, environment variables for a single process) so this is negligible.

**Test impact:** Every rule has dedicated unit tests with handcrafted `ScanData` containing exactly the data needed to trigger pass/fail/NotApplicable.

---

## Pattern 5 — String Span Parsing for Performance

**What:** `ReadStatusAsync` uses `ReadOnlySpan<char>` operations to avoid intermediate string allocations.

```csharp
if (line.StartsWith("PPid:", StringComparison.OrdinalIgnoreCase))
    int.TryParse(line.AsSpan(5).TrimStart(), out ppid);
```

**Why it matters:** `/proc/<pid>/status` is read for every process. Span-based parsing avoids heap pressure from substring allocations.

**Trade-off:** `AsSpan().TrimStart().ToString()` is still used for `Name` and `State` because they must be stored as strings. The numeric fields (`PPid`, `Uid`) parse directly from spans.

**Test impact:** Parser behavior is verified through the scanner's integration with the rule tests.

---

## Pattern 6 — Shared Visibility Helpers

**What:** All six rules use shared helpers to determine process-data availability and evidence-specific readability.

```csharp
private static bool HasProcessDataAvailable(ScanData data)
{
    if (data.ProcessRuntimes.Count > 0) return true;
    return data.Capabilities.Any(c =>
        c.SourceName.Equals("/proc", OrdinalIgnoreCase) &&
        c.Status is Available or PermissionLimited);
}

public static bool HasReadableMaps(ProcessRuntimeEntry proc) =>
    proc.MemoryMapsReadable || proc.MemoryMaps.Count > 0;
```

**Why it matters:** Consistent NotApplicable semantics across all rules. If `/proc` was partially readable (`PermissionLimited`), rules evaluate the readable subset, surface unreadable-count metadata, and avoid claiming a clean pass when the required evidence was entirely unreadable.

**Trade-off:** The scanner must carry readability flags separately from collection contents, because an empty-but-readable procfs file and an unreadable procfs file mean different things.

**Test impact:** Rule tests cover no process data, all evidence unreadable, partial unreadable metadata, and normal pass/fail behavior.

---

## Pattern 7 — Metadata String Capping

**What:** `target` and `allPids` strings are capped at 500 characters with `"..."` suffix to prevent oversized metadata.

```csharp
var allPids = string.Join(",", violations.Select(v => v.Pid));
if (allPids.Length > 500)
    allPids = allPids[..497] + "...";
```

**Why it matters:** Rule metadata flows into `Finding.Variables`, explanation templates, evidence exports, and JSON serialization. Uncapped strings could produce multi-megabyte findings.

**Trade-off:** Very large violation sets lose individual PID detail. The `count` field preserves the total.

**Test impact:** Verified implicitly through the fact that tests pass with small violation sets.

---

## Summary

| Pattern | Where | Benefit |
|---|---|---|
| TryReadAsync | Scanner | Clean per-file fault isolation |
| Bounded MemoryStream | Scanner | Memory-safe procfs reads with truncation signal |
| Value tuple returns | Scanner | Explicit metadata coupling, zero-allocation |
| LINQ enumeration | Rules | Declarative, testable rule logic |
| Span parsing | Scanner | Reduced heap pressure on status parsing |
| Shared NotApplicable helper | Rules | Consistent semantics across all PROC rules |
| String capping | Rules | Prevents oversized metadata in exports |
