# Attack Scenario: Runtime Process Threat Hunting

> A worked example showing how the scanner and rules detect a live multi-stage compromise.

---

## Scenario Setup

An attacker has gained initial access to a web server via a vulnerable upload endpoint. The attack proceeds in three stages:

1. **Payload drop** — The attacker uploads a reverse-shell binary to `/dev/shm/.rshell`
2. **Execution** — The attacker triggers execution through a crafted HTTP request; the web server (`apache2`) spawns the payload as a child process
3. **Persistence** — The payload sets `LD_PRELOAD=/dev/shm/.hook.so`, injects a hook into `sshd`, and deletes its own binary from disk

---

## Stage 1 — Payload Drop

The attacker uploads a file to `/dev/shm/.rshell`. At this point:

- No process is running the file yet
- `FilesystemAuditScanner` might detect `/dev/shm/.rshell` as a world-writable file (FSYS-001)
- `ProcessRuntimeScanner` sees nothing unusual

---

## Stage 2 — Execution and Parent-Child Anomaly

The attacker sends an HTTP request that triggers the web server to execute the uploaded file.

### Live /proc State

| Process | Pid | Ppid | Name | ExePath | Environment |
|---|---|---|---|---|---|
| apache2 | 100 | 1 | apache2 | /usr/sbin/apache2 | `PATH=...` |
| .rshell | 200 | 100 | .rshell | /dev/shm/.rshell | `PATH=...` |

### Rule Detection

**PROC-005 — Suspicious Parent-Child Relationship** fires:

```
Parent: apache2[100] -> Child: .rshell[200]
```

`IsSuspiciousPair("apache2", ".rshell")` evaluates:
- `parentLower` is `"apache2"` → matches web-server condition
- `childLower` is `".rshell"` → `IsInterpreter(".rshell")` returns false (not a known interpreter)
- **Result:** No violation from PROC-005

Wait — `.rshell` is not an interpreter, so PROC-005 does not fire here. But what if the attacker uses a more subtle approach?

### Alternative: Interpreter Spawn

The attacker instead triggers execution of a Python reverse shell:

| Process | Pid | Ppid | Name | ExePath | Cmdline |
|---|---|---|---|---|---|
| apache2 | 100 | 1 | apache2 | /usr/sbin/apache2 | ... |
| python3 | 200 | 100 | python3 | /usr/bin/python3.11 | `python3 -c 'import socket...'` |

**PROC-005 fires:**

```
Parent: apache2[100] -> Child: python3[200]
```

- `parentLower` is `"apache2"` → matches web-server condition
- `childLower` is `"python3"` → `IsInterpreter("python3")` returns true
- **Result:** PROC-005 FAIL with severity High

The analyst sees:
- `count: 1`
- `firstChildPid: 200`
- `firstChildName: python3`
- `firstParentName: apache2`
- Explanation template surfaces verification commands: `ps -fp 200`, `ss -p | grep 200`, `lsof -p 200`

---

## Stage 3 — Persistence and Anti-Forensics

The payload now:
1. Sets `LD_PRELOAD=/dev/shm/.hook.so` in its own environment
2. Injects the hook into `sshd` via some mechanism
3. Deletes `/dev/shm/.rshell` from disk while still running
4. Forks a daemonized child that parents itself to `init` with a random name

### Live /proc State After Stage 3

| Process | Pid | Ppid | Name | ExePath | Environment | MemoryMaps |
|---|---|---|---|---|---|---|
| .rshell | 200 | 100 | .rshell | `/dev/shm/.rshell (deleted)` | `LD_PRELOAD=/dev/shm/.hook.so` | ... |
| xk9j2m4p7q | 300 | 1 | xk9j2m4p7q | `/dev/shm/xk9j2m4p7q (deleted)` | ... | ... |
| sshd | 400 | 1 | sshd | /usr/sbin/sshd | ... | contains rwxp region |

### Rule Detection — PROC-003 (Deleted Binary)

`.rshell` has `ExePath = "/dev/shm/.rshell (deleted)"`.

`DeletedBinaryExecutionRule` evaluates:
- `exe.EndsWith(" (deleted)", Ordinal)` → **true**
- **Result:** PROC-003 FAIL with severity High

`xk9j2m4p7q` also has a deleted exe path.
- **Result:** PROC-003 FAIL, `count: 2`

The analyst sees:
- `firstPid: 200`
- `firstName: .rshell`
- `firstExePath: /dev/shm/.rshell (deleted)`
- Verification: `ls -la /proc/200/exe`, `cp /proc/200/exe /tmp/recovered`

### Rule Detection — PROC-002 (LD_PRELOAD Injection)

`.rshell` has `Environment = ["LD_PRELOAD=/dev/shm/.hook.so", "PATH=..."]`.

`LdPreloadInjectionRule` evaluates:
- `env.StartsWith("LD_PRELOAD=", OrdinalIgnoreCase)` → **true**
- Value `/dev/shm/.hook.so` is not empty
- **Result:** PROC-002 FAIL with severity High

The analyst sees:
- `firstPid: 200`
- `firstName: .rshell`
- `firstVariable: LD_PRELOAD=/dev/shm/.hook.so`
- Verification: `cat /proc/200/environ | tr '\0' '\n' | grep LD_`

### Rule Detection — PROC-004 (Orphaned Anomalous Process)

`xk9j2m4p7q` has `Ppid = 1`.

`OrphanedAnomalousProcessRule` evaluates:
- `Ppid == 1` → **true**
- `IsAnomalousName("xk9j2m4p7q")`:
  - Length = 10 ≥ 10 → pass
  - All alphanumeric → pass
  - Digits = 3 ≥ 3 → pass
- **Result:** PROC-004 FAIL with severity Medium

The analyst sees:
- `firstPid: 300`
- `firstName: xk9j2m4p7q`
- `firstCmdline: ...`
- Verification: `ps -fp 300`, `pstree -p 300`

### Rule Detection — PROC-001 (RWX Memory Mapping)

The injected hook in `sshd` creates an RWX memory region for shellcode.

`RwxMemoryRegionRule` evaluates `sshd`'s `MemoryMaps`:
- One map has `Permissions = "rwxp"`
- `Permissions[0] == 'r' && Permissions[1] == 'w' && Permissions[2] == 'x'` → **true**
- **Result:** PROC-001 FAIL with severity Critical

The analyst sees:
- `firstPid: 400`
- `firstName: sshd`
- `firstCmdline: ...`
- Verification: `cat /proc/400/maps | grep rwx`

---

## Combined Detection Summary

| Stage | Rule | Severity | What It Reveals |
|---|---|---|---|
| Stage 2 | PROC-005 | High | Web server spawning an interpreter — RCE indicator |
| Stage 3 | PROC-003 | High | Process running a deleted binary — anti-forensics |
| Stage 3 | PROC-002 | High | Dynamic linker hijacking — persistence |
| Stage 3 | PROC-004 | Medium | Orphaned random-name process — daemonized backdoor |
| Stage 3 | PROC-001 | Critical | RWX memory in sshd — process injection |

---

## Why This Matters

A configuration audit at any stage would show:
- SSH config is hardened (SSH-001..008 pass)
- Firewall is active (FW-001..005 pass)
- File permissions are correct (FILE-001..007 pass)
- No suspicious cron jobs (CRON-001..003 pass)

The **only** signals of the active compromise are in live process state. Without runtime process threat hunting, the attacker would remain undetected until they triggered a log-based detector (e.g., beaconing from the reverse shell) or a file-based scanner (e.g., YARA match on the dropped payload).

Runtime process inspection closes the gap between "the system looks configured correctly" and "the system is currently compromised."