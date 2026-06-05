# Quick Reference: Runtime Process Threat Hunting

## Rule Table

| Rule | Name | Severity | What It Checks | Data Source |
|---|---|---|---|---|
| PROC-001 | RWX Memory Mapping | Critical | `/proc/<pid>/maps` regions with `rwxp` permissions | `/proc/<pid>/maps` |
| PROC-002 | LD_PRELOAD / LD_AUDIT Injection | High | `LD_PRELOAD=` or `LD_AUDIT=` in `/proc/<pid>/environ` | `/proc/<pid>/environ` |
| PROC-003 | Deleted Binary / Temp-Path Execution | High | `/proc/<pid>/exe` ending in ` (deleted)` or residing under `/tmp`, `/var/tmp`, `/dev/shm` | `readlink /proc/<pid>/exe` |
| PROC-004 | Orphaned Anomalous Process | Medium | PPid=1 with name ≥10 chars, alphanumeric, ≥3 digits | `/proc/<pid>/status`, `/proc/<pid>/comm` |
| PROC-005 | Suspicious Parent-Child Relationship | High | Network services, SSH, databases, or cron spawning shells/interpreters | `/proc/<pid>/status`, `/proc/<pid>/comm` |
| PROC-006 | Interpreter RWX Memory Mapping | Critical | python/perl/ruby/php processes with `rwxp` memory mappings | `/proc/<pid>/comm`, `/proc/<pid>/cmdline`, `/proc/<pid>/exe`, `/proc/<pid>/maps` |

## Scanner Configuration

| Parameter | Value | Purpose |
|---|---|---|
| `MaxConcurrency` | 50 | `SemaphoreSlim` bound for concurrent process reads |
| `MaxCmdlineBytes` | 65 536 | `/proc/<pid>/cmdline` read cap |
| `MaxEnvironBytes` | 262 144 | `/proc/<pid>/environ` read cap |
| `MaxMapsBytes` | 524 288 | `/proc/<pid>/maps` read cap |

## ProcessRuntimeEntry Fields

| Field | Source | Notes |
|---|---|---|
| `Pid` | Directory name | Parsed from `/proc/<pid>` |
| `Name` | `/proc/<pid>/comm` | Falls back to `status.Name` if `comm` unreadable |
| `ExePath` | `readlink /proc/<pid>/exe` | Empty string if unreadable |
| `Cmdline` | `/proc/<pid>/cmdline` | Null bytes replaced with spaces; empty if unreadable |
| `Ppid` | `/proc/<pid>/status` | Parent PID from `PPid:` line |
| `Uid` | `/proc/<pid>/status` | Real UID from first `Uid:` field |
| `MemoryMaps` | `/proc/<pid>/maps` | Parsed into `ProcessMemoryMap` records with validated address ranges and permissions |
| `MemoryMapsReadable` | `/proc/<pid>/maps` | True when maps were readable, even if empty |
| `Environment` | `/proc/<pid>/environ` | Split on null bytes into `key=value` strings |
| `EnvironmentReadable` | `/proc/<pid>/environ` | True when environ was readable, even if empty |
| `CmdlineReadable` | `/proc/<pid>/cmdline` | True when cmdline was readable, even if empty |
| `ExePathReadable` | `readlink /proc/<pid>/exe` | True when exe resolution succeeded |
| `StatusDuplicateFieldCount` | `/proc/<pid>/status` | Non-zero indicates duplicate headers (anomalous/tampered input) |
| `CmdlineTruncated` | `/proc/<pid>/cmdline` | True when file exceeded 64 KB cap |
| `EnvironTruncated` | `/proc/<pid>/environ` | True when file exceeded 256 KB cap |
| `MapsTruncated` | `/proc/<pid>/maps` | True when file exceeded 512 KB cap |

## Rule Metadata (Variables)

### PROC-001 — Fail
- `count` — number of violating processes
- `firstPid` — PID of first violation
- `firstName` — name of first violation
- `firstCmdline` — cmdline of first violation
- `allPids` — comma-separated PIDs of all violations (capped at 500 chars)
- `mapsTruncated` — `"true"` if any process had truncated maps
- `mapsUnreadableCount` — processes whose maps were unreadable

### PROC-002 — Fail
- `count` — number of violating processes
- `firstPid` — PID of first violation
- `firstName` — name of first violation
- `firstVariable` — full env var string of first violation
- `allPids` — comma-separated PIDs (capped at 500 chars)
- `environTruncated` — `"true"` if any process had truncated environ
- `environUnreadableCount` — processes whose environ files were unreadable

### PROC-003 — Fail
- `count` — number of violating processes
- `firstPid` — PID of first violation
- `firstName` — name of first violation
- `firstExePath` — exe path of first violation
- `allPids` — comma-separated PIDs (capped at 500 chars)
- `exeUnreadableCount` — processes whose exe symlink could not be resolved

### PROC-004 — Fail
- `count` — number of violating processes
- `firstPid` — PID of first violation
- `firstName` — name of first violation
- `firstCmdline` — cmdline of first violation
- `allPids` — comma-separated PIDs (capped at 500 chars)

### PROC-005 — Fail
- `count` — number of suspicious relationships
- `firstChildPid` — PID of first violating child
- `firstChildName` — name of first violating child
- `firstParentName` — name of first violating parent
- `allPids` — comma-separated child PIDs (capped at 500 chars)
- `missingParentCount` — processes whose PPid was not in the snapshot
- `totalChecked` — processes with PPid > 0 that were evaluated

### PROC-005 — Pass (no violations)
- `missingParentCount` — processes whose PPid was not in the snapshot
- `totalChecked` — processes with PPid > 0 that were evaluated

### PROC-006 — Fail
- `count` — number of violating interpreter processes
- `firstPid` — PID of first violation
- `firstName` — name of first violation
- `firstCmdline` — cmdline of first violation
- `firstMapPath` — mapped path for the first RWX region, if present
- `allPids` — comma-separated PIDs (capped at 500 chars)
- `mapsTruncated` — `"true"` if any process had truncated maps
- `mapsUnreadableCount` — processes whose maps were unreadable

## Anomalous Name Criteria (PROC-004)

| Criterion | Requirement |
|---|---|
| Length | ≥ 10 characters |
| Characters | Entirely alphanumeric (`char.IsLetterOrDigit`) |
| Digits | ≥ 3 digits |

## Suspicious Pair Matrix (PROC-005)

| Parent | Child Trigger |
|---|---|
| `apache2`, `nginx`, `httpd*` | Any interpreter (bash, python, perl, ruby, php, versioned variants) |
| `sshd` | Any interpreter except `bash`, `sh`, `dash`, `zsh` |
| `mysqld`, `mongod`, `redis-server`, `postgres*` | Any interpreter |
| `cron`, `crond` | Any interpreter, `curl`, `wget`, `nc`, `ncat` |

## MITRE ATT&CK Techniques

| Rule | Technique | Tactic |
|---|---|---|
| PROC-001 | T1055 — Process Injection | Defense Evasion |
| PROC-001 | T1620 — Reflective Code Loading | Defense Evasion |
| PROC-002 | T1574.006 — Dynamic Linker Hijacking | Persistence, Privilege Escalation |
| PROC-003 | T1036 — Masquerading | Defense Evasion |
| PROC-003 | T1105 — Ingress Tool Transfer | Command and Control |
| PROC-004 | T1036 — Masquerading | Defense Evasion |
| PROC-005 | T1059 — Command and Scripting Interpreter | Execution |
| PROC-006 | T1055 — Process Injection | Defense Evasion |
| PROC-006 | T1620 — Reflective Code Loading | Defense Evasion |
| PROC-006 | T1059 — Command and Scripting Interpreter | Execution |

## Query Parser Keywords

Users can ask:
- "check my processes"
- "check running processes"
- "process runtime"
- "check process runtime"
- "runtime process check"

These map to `AgentIntent.ProcessRuntimeCheck`.

## NotApplicable Condition

All six rules return `NotApplicable` when:
- `data.ProcessRuntimes` is empty, **and**
- No `/proc` capability has status `Available` or `PermissionLimited`

Evidence-specific rules also return `NotApplicable` when their required data is entirely unreadable:
- PROC-001 and PROC-006 require readable `/proc/<pid>/maps`
- PROC-002 requires readable `/proc/<pid>/environ`
- PROC-003 requires readable `/proc/<pid>/exe`
