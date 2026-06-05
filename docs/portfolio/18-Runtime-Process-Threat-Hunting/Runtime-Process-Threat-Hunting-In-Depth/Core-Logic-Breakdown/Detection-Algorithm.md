# Detection Algorithm: Runtime Process Threat Hunting

## Scanner Pipeline

### Step 1 — Enumerate PIDs

```csharp
var procEntries = Directory.GetDirectories("/proc")
    .Select(Path.GetFileName)
    .Where(name => name != null && name.All(char.IsDigit))
    .Select(name => int.Parse(name!))
    .ToList();
```

All numeric directories in `/proc/` are treated as process IDs. Non-numeric directories (e.g., `sys`, `irq`, `self`) are skipped.

### Step 2 — Bounded Concurrent Read

A `SemaphoreSlim(50, 50)` limits concurrent `Task` creation. For each PID:

1. `await semaphore.WaitAsync(cancellationToken)`
2. Start `ReadProcessAsync(pid, semaphore, ct)` as a fire-and-forget task
3. Inside `ReadProcessAsync`, the semaphore is released after all six files are read (or on exception)

This bounds concurrent `readlink` and procfs reads without blocking the enumeration loop.

### Step 3 — Per-Process File Reading

`ReadProcessAsync` reads six sources, each wrapped in `TryReadAsync`:

| File | Method | Returns | Fallback |
|---|---|---|---|
| `/proc/<pid>/status` | `ReadStatusAsync` | `ProcessStatus?` | `null` (process skipped) |
| `/proc/<pid>/comm` | `ReadCommAsync` | `string?` | `status.Name` |
| `/proc/<pid>/exe` | `ReadExePathAsync` | `string?` | `string.Empty` |
| `/proc/<pid>/cmdline` | `ReadCmdlineAsync` | `(string? Content, bool Truncated)` | `string.Empty, false` |
| `/proc/<pid>/maps` | `ReadMapsAsync` | `(List<ProcessMemoryMap>? Maps, bool Truncated)` | `Empty, false` |
| `/proc/<pid>/environ` | `ReadEnvironAsync` | `(List<string>? Entries, bool Truncated)` | `Empty, false` |

`TryReadAsync` catches non-cancellation exceptions and returns `default(T)`, so one unreadable file does not drop the entire process.

### Step 4 — Status Parsing with Duplicate Guard

`ReadStatusAsync` parses `PPid`, `Uid`, `Name`, and `State` lines. It tracks `seenPpid`, `seenUid`, `seenName`, `seenState` booleans. If a duplicate header is encountered, `duplicateCount` increments. The first value wins (not the last), making appended tampering harder than prepended tampering.

### Step 5 — Procfs Read Loops

`ReadProcFileAsync` opens a `FileStream` and reads into a `MemoryStream` with a byte cap:

```csharp
while (totalRead < maxBytes)
{
    int toRead = Math.Min(buffer.Length, maxBytes - totalRead);
    int read = await fs.ReadAsync(buffer.AsMemory(0, toRead), ct);
    if (read == 0) break;
    ms.Write(buffer, 0, read);
    totalRead += read;
}
```

After the loop, if `totalRead >= maxBytes`, a 1-byte peek read determines whether the file continues. This distinguishes "exactly maxBytes" from "exceeded maxBytes."

### Step 6 — Map Line Parsing

`ParseMapLine` validates every line of `/proc/<pid>/maps`:

1. Split on spaces → require ≥ 5 parts
2. `addressRange` must match `hex-hex` pattern (validated by `IsValidAddressRange` + `IsHex`)
3. `perms` must be exactly 4 characters, each in `{'r','w','x','p','s','-'}`
4. Path (parts[5..]) is joined with spaces to handle paths containing spaces

Invalid lines are skipped silently — they do not crash the scanner.

### Step 7 — Result Assembly

`ReadProcessAsync` assembles a `ProcessRuntimeEntry` with all fields, including truncation flags and `StatusDuplicateFieldCount`.

### Step 8 — Capability Reporting

After all tasks complete, the scanner reports `/proc` capability status:

- `Available` — at least one process was readable with no permission issues
- `PermissionLimited` — at least one process was readable, but some had all-empty fields (indicating permission-limited reads)
- `Unavailable` — no processes were readable
- On outer exception: `Unavailable` with `Detail = "Error: ..."`

---

## Rule Evaluation

### PROC-001 — RWX Memory Mapping

```csharp
proc.MemoryMaps.Any(m => m.Permissions.Length >= 3
    && m.Permissions[0] == 'r'
    && m.Permissions[1] == 'w'
    && m.Permissions[2] == 'x')
```

Explicit character checks (not `Contains`) prevent false positives from permission strings like `rwx!`.

### PROC-002 — LD_PRELOAD / LD_AUDIT Injection

```csharp
foreach (var env in proc.Environment)
{
    if (env.StartsWith("LD_PRELOAD=", OrdinalIgnoreCase))
    {
        var value = env.AsSpan("LD_PRELOAD=".Length).Trim().ToString();
        if (!string.IsNullOrEmpty(value))
            violations.Add((proc, env));
    }
    else if (env.StartsWith("LD_AUDIT=", OrdinalIgnoreCase))
    {
        var value = env.AsSpan("LD_AUDIT=".Length).Trim().ToString();
        if (!string.IsNullOrEmpty(value))
            violations.Add((proc, env));
    }
}
```

Empty values (`LD_PRELOAD=`) are ignored. The full env var string is preserved for the explanation template.

### PROC-003 — Deleted Binary / Temp-Path Execution

```csharp
if (exe.EndsWith(" (deleted)", Ordinal))
    violations.Add(proc);

foreach (var prefix in TempPathPrefixes) // /tmp/, /var/tmp/, /dev/shm/
    if (exe.StartsWith(prefix, Ordinal))
        violations.Add(proc);

foreach (var exact in TempPathExactMatches) // /tmp, /var/tmp, /dev/shm
    if (exe.Equals(exact, Ordinal))
        violations.Add(proc);
```

Uses `EndsWith(" (deleted)", Ordinal)` with a leading space — not `Contains` — to avoid matching paths like `/tmp/not-deleted`.

### PROC-004 — Orphaned Anomalous Process

```csharp
if (proc.Ppid != 1) continue;
if (IsAnomalousName(proc.Name)) violations.Add(proc);

// IsAnomalousName:
// - Length >= 10
// - All alphanumeric
// - At least 3 digits
```

### PROC-005 — Suspicious Parent-Child Relationship

```csharp
var pidToName = data.ProcessRuntimes
    .GroupBy(p => p.Pid)
    .ToDictionary(g => g.Key, g => g.First().Name);

foreach (var proc in data.ProcessRuntimes)
{
    if (proc.Ppid <= 0) continue;
    if (!pidToName.TryGetValue(proc.Ppid, out var parentName))
    {
        missingParentCount++;
        continue;
    }
    if (IsSuspiciousPair(parentName, proc.Name))
        violations.Add((Child: proc, ParentName: parentName));
}
```

`IsSuspiciousPair` uses exact match / `StartsWith` for parent names:

```csharp
if (parentLower is "apache2" or "nginx" || parentLower.StartsWith("httpd", Ordinal))
    if (IsInterpreter(childLower)) return true;

if (parentLower == "sshd")
    if (IsInterpreter(childLower) && childLower is not "bash" and not "sh" and not "dash" and not "zsh")
        return true;
```

`IsInterpreter` handles versioned names:

```csharp
if (name.StartsWith("python", Ordinal) && name.Length > 6 && char.IsDigit(name[6]))
    return true; // python3.11
```

### PROC-006 — Interpreter RWX Memory Mapping

```csharp
ProcessRuntimeRuleHelpers.IsInterpreterProcess(proc) &&
ProcessRuntimeRuleHelpers.HasRwxMap(proc)
```

The interpreter check considers process name, executable path, and command line so versioned binaries such as `python3.11`, `perl5.34`, `ruby3.2`, and `php8.1` are still detected. This keeps the generic RWX rule intact while adding a higher-signal finding for interpreter-hosted payloads.

---

## Metadata Flow

| Metadata Key | Source | Meaning |
|---|---|---|
| `mapsTruncated` | Any `ProcessRuntimeEntry.MapsTruncated == true` | At least one process had truncated `/proc/<pid>/maps` |
| `environTruncated` | Any `ProcessRuntimeEntry.EnvironTruncated == true` | At least one process had truncated `/proc/<pid>/environ` |
| `mapsUnreadableCount` | PROC-001/PROC-006 readable-map filter | Processes whose `/proc/<pid>/maps` could not be read |
| `environUnreadableCount` | PROC-002 readable-environ filter | Processes whose `/proc/<pid>/environ` could not be read |
| `exeUnreadableCount` | PROC-003 readable-exe filter | Processes whose `/proc/<pid>/exe` could not be resolved |
| `missingParentCount` | PROC-005 internal counter | Processes whose PPid was not in the snapshot |
| `totalChecked` | PROC-005 internal counter | Processes with PPid > 0 that were evaluated |
| `allPids` | Rule-specific | Comma-separated PIDs of all violating processes (capped at 500 chars) |

---

## NotApplicable Logic

All six rules share the same `HasProcessDataAvailable` check:

```csharp
if (data.ProcessRuntimes.Count > 0) return true;
return data.Capabilities.Any(c =>
    c.SourceName.Equals("/proc", OrdinalIgnoreCase) &&
    c.Status is Available or PermissionLimited);
```

If `/proc` is completely unreadable, the rule returns `NotApplicable` with an explanation noting that `/proc` access is required.

Evidence-specific rules add a second check for their required file type. PROC-001 and PROC-006 require readable maps, PROC-002 requires readable environment data, and PROC-003 requires readable executable symlinks. If every process is unreadable for the required evidence, the rule returns `NotApplicable` instead of a misleading clean pass.
