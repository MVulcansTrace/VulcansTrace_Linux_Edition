## PROC-001

**What we found:** {{count}} process(es) have memory mappings with read-write-execute (RWX) permissions. The first is {{firstName}}[PID {{firstPid}}] with cmdline: {{firstCmdline}}.

**Why this matters:** RWX memory regions are highly abnormal for legitimate Linux processes. They are a classic indicator of process injection, position-independent shellcode, or reflective loading where an attacker writes executable code directly into a process's address space. Modern exploit frameworks and malware frequently allocate RWX pages to stage payloads.

**How to verify:**
1. Inspect the process memory maps directly: `cat /proc/{{firstPid}}/maps | grep rwx`
2. Check the process executable and cmdline: `ls -la /proc/{{firstPid}}/exe` and `cat /proc/{{firstPid}}/cmdline | tr '\0' ' '`
3. Inspect open file descriptors: `ls -la /proc/{{firstPid}}/fd/`
4. Check if the process is expected: `ps -fp {{firstPid}}` and compare against your baseline.
5. Use `pmap {{firstPid}}` to visualize the address space.

**Backup commands:**
1. Capture process memory maps: `cat /proc/{{firstPid}}/maps > /tmp/proc-{{firstPid}}-maps-$(date +%s).txt`
2. Record process status: `cat /proc/{{firstPid}}/status > /tmp/proc-{{firstPid}}-status-$(date +%s).txt`

**Suggested next action:**
1. Treat RWX findings as strongly suspicious. Do not immediately kill the process if you need to investigate.
2. Compare the process against your software inventory and configuration baseline.
3. If the process is not legitimate, capture a memory dump for forensics before terminating: `gcore {{firstPid}}` (if gdb is available) or `cat /proc/{{firstPid}}/mem` to a file.
4. Kill the process: `kill -9 {{firstPid}}`
5. Review system logs (`journalctl`, `/var/log/syslog`) for how the process was launched.

**Rollback commands:**
1. If a legitimate process was killed, restart it through the normal service manager: `systemctl restart <service>`
2. Restore any backed-up configurations from your known-good baseline.

**Risk level:** CRITICAL

**Confidence / caveat:** High confidence — RWX mappings are extremely rare in well-hardened production systems. Some JIT compilers (e.g., Java, .NET) may legitimately use RWX during startup before transitioning to RX. Verify the process identity before acting.

---

## PROC-002

**What we found:** {{count}} process(es) have `LD_PRELOAD` or `LD_AUDIT` set in their environment. The first is {{firstName}}[PID {{firstPid}}] with variable: {{firstVariable}}.

**Why this matters:** `LD_PRELOAD` forces the dynamic linker to load a specified shared library before all others, allowing an attacker to hook and replace standard library functions. `LD_AUDIT` provides similar interception capabilities. This is a common Linux persistence and credential-harvesting technique used by rootkits and malicious loaders.

**How to verify:**
1. Inspect the environment directly: `cat /proc/{{firstPid}}/environ | tr '\0' '\n' | grep -i LD_`
2. Check if the preloaded library exists and is legitimate: `ls -la <path-from-variable>`
3. Verify the library's hash against a known-good baseline.
4. Check which other processes share the same environment: `grep -r "LD_PRELOAD" /proc/*/environ 2>/dev/null`

**Backup commands:**
1. Save the environment: `cat /proc/{{firstPid}}/environ | tr '\0' '\n' > /tmp/proc-{{firstPid}}-env-$(date +%s).txt`
2. Save the loaded library if present: `cp <path> /tmp/ldpreload-$(date +%s).bak`

**Suggested next action:**
1. Investigate whether the `LD_PRELOAD`/`LD_AUDIT` value is expected for this application.
2. If unexpected, inspect the loaded library with `strings`, `ldd`, and `objdump`.
3. Remove the malicious library from disk if confirmed bad.
4. Restart the affected process or service to clear the injected library from memory.
5. Check cron jobs, systemd units, and shell profiles for where the variable is being set persistently.

**Rollback commands:**
1. If a legitimate library was removed, restore it from the backup.
2. If a service was restarted, confirm it is functioning correctly.

**Risk level:** HIGH

**Confidence / caveat:** High confidence for unexpected values. Some legitimate debugging, monitoring, or compatibility tools may use `LD_PRELOAD`. Always verify the target library path before remediation.

---

## PROC-003

**What we found:** {{count}} process(es) are executing from a deleted binary or a temporary path. The first is {{firstName}}[PID {{firstPid}}] with executable path: {{firstExePath}}.

**Why this matters:** Execution from `/tmp`, `/var/tmp`, or `/dev/shm` is a common pattern for dropped payloads and staging tools. A `(deleted)` suffix on `/proc/<pid>/exe` indicates the original binary was removed from disk while still running — a classic anti-forensics technique used by malware to prevent file-based detection and analysis.

**How to verify:**
1. Confirm the executable status: `ls -la /proc/{{firstPid}}/exe`
2. Check the process cmdline: `cat /proc/{{firstPid}}/cmdline | tr '\0' ' '`
3. Inspect open files and working directory: `ls -la /proc/{{firstPid}}/fd/` and `ls -ld /proc/{{firstPid}}/cwd`
4. Check process start time and parent: `ps -fp {{firstPid}}` and `cat /proc/{{firstPid}}/status | grep PPid`
5. Review recent `/tmp` contents from backups or audit logs if the file was deleted.

**Backup commands:**
1. Dump the process executable from memory: `cp /proc/{{firstPid}}/exe /tmp/recovered-exe-{{firstPid}}-$(date +%s)`
2. Record process metadata: `cat /proc/{{firstPid}}/status > /tmp/proc-{{firstPid}}-status-$(date +%s).txt`

**Suggested next action:**
1. Attempt to recover the binary from `/proc/{{firstPid}}/exe` before terminating.
2. Hash the recovered binary and scan it with YARA or submit for analysis.
3. Terminate the process: `kill -9 {{firstPid}}`
4. Review system logs and audit trails for how the binary was initially dropped and executed.
5. Check for related persistence mechanisms (cron, systemd, rc.local, shell profiles).

**Rollback commands:**
1. If the process was legitimate, restore the binary from backup and restart the application.
2. Verify no dependent services were disrupted.

**Risk level:** HIGH

**Confidence / caveat:** Very high confidence for `(deleted)` binaries. Temporary-path execution has legitimate use cases (e.g., some build systems, container runtimes), but should still be reviewed in production environments.

---

## PROC-004

**What we found:** {{count}} orphaned process(es) with anomalous names detected running under init (PPid=1). The first is {{firstName}}[PID {{firstPid}}] with cmdline: {{firstCmdline}}.

**Why this matters:** Processes that are direct children of `init` (PID 1) with randomly generated alphanumeric names are a strong indicator of daemonized malware or persistence mechanisms. Attackers often use random names to evade signature-based detection and parent themselves to init so they survive terminal session closure.

**How to verify:**
1. Inspect the process tree: `ps -fp {{firstPid}}` and `pstree -p {{firstPid}}`
2. Check the executable and cmdline: `ls -la /proc/{{firstPid}}/exe` and `cat /proc/{{firstPid}}/cmdline | tr '\0' ' '`
3. Inspect open network connections: `ss -p | grep {{firstPid}}` or `lsof -p {{firstPid}} | grep IPv`
4. Review when the process started: `ps -o lstart= -p {{firstPid}}`
5. Check systemd for related services: `systemctl list-units --type=service | grep -i {{firstName}}`

**Backup commands:**
1. Record full process details: `ps auxww | grep {{firstPid}} > /tmp/proc-{{firstPid}}-details-$(date +%s).txt`
2. Capture open files: `lsof -p {{firstPid}} > /tmp/proc-{{firstPid}}-lsof-$(date +%s).txt`

**Suggested next action:**
1. Verify whether the process belongs to a known package: `dpkg -S /proc/{{firstPid}}/exe` (may fail for deleted binaries).
2. Check if it is a known systemd service with an unusual display name.
3. If unaccounted for, capture the binary from `/proc/{{firstPid}}/exe` for analysis.
4. Terminate if confirmed malicious: `kill -9 {{firstPid}}`
5. Search for startup scripts, cron jobs, or systemd units that may respawn it.

**Rollback commands:**
1. If a legitimate background service was stopped, restart it via `systemctl start <service>`.

**Risk level:** MEDIUM

**Confidence / caveat:** Medium-high confidence. Some container runtimes, custom daemons, or language runtimes may produce init-parented processes with unusual names. Always cross-reference against your software inventory.

---

## PROC-005

**What we found:** {{count}} suspicious parent-child process relationship(s). The first is {{firstParentName}} -> {{firstChildName}}[PID {{firstChildPid}}].

**Why this matters:** Network-facing services (web servers, SSH, databases) should not spawn interactive shells or scripting interpreters. When they do, it is a strong indicator of remote code execution, webshells, SQL injection with shell access, or successful exploitation. Cron spawning network tools suggests a malicious scheduled payload.

**How to verify:**
1. Inspect both processes: `ps -fp {{firstChildPid}}` and `ps -fp $(cat /proc/{{firstChildPid}}/status | grep PPid | awk '{print $2}')`
2. Check the child's command line and working directory: `cat /proc/{{firstChildPid}}/cmdline | tr '\0' ' '` and `ls -ld /proc/{{firstChildPid}}/cwd`
3. Inspect network activity: `ss -p | grep {{firstChildPid}}` and `lsof -p {{firstChildPid}} | grep IPv`
4. Review service logs (apache, nginx, sshd) around the process start time.
5. Check if the child is a legitimate maintenance script or expected CGI execution.

**Backup commands:**
1. Record process details: `ps auxww | grep -E '{{firstChildPid}}|{{firstParentName}}' > /tmp/parent-child-$(date +%s).txt`
2. Capture open files: `lsof -p {{firstChildPid}} > /tmp/proc-{{firstChildPid}}-lsof-$(date +%s).txt`

**Suggested next action:**
1. Determine if the child process is expected for your application stack.
2. If unexpected, inspect the parent service logs for exploitation evidence (e.g., webshell uploads, suspicious HTTP requests).
3. Kill the child process if it is an attacker shell: `kill -9 {{firstChildPid}}`
4. Harden the parent service (e.g., disable dangerous functions in PHP, restrict database user privileges, apply WAF rules).
5. Patch the parent service if exploitation is confirmed.

**Rollback commands:**
1. If a legitimate maintenance task was killed, reschedule it properly.
2. If service hardening broke functionality, revert the specific restrictive configuration.

**Risk level:** HIGH

**Confidence / caveat:** High confidence for network services spawning unexpected interpreters. Some valid scenarios exist (e.g., application-specific child workers, PHP-FPM, WSGI processes). Always verify against the application's expected behavior.

---

## PROC-006

**What we found:** {{count}} interpreter process(es) have memory mappings with read-write-execute (RWX) permissions. The first is {{firstName}}[PID {{firstPid}}] with cmdline: {{firstCmdline}}.

**Why this matters:** Python, Perl, Ruby, and PHP processes can legitimately execute scripts, but steady-state RWX memory in an interpreter is a stronger signal for in-memory payload execution, `-c`/eval-style loaders, shellcode staging, or native extension abuse. This finding preserves the generic RWX injection signal while calling out the higher-risk interpreter context.

**How to verify:**
1. Inspect the interpreter maps directly: `cat /proc/{{firstPid}}/maps | grep rwx`
2. Check the interpreter command line: `cat /proc/{{firstPid}}/cmdline | tr '\0' ' '`
3. Inspect the executable and working directory: `ls -la /proc/{{firstPid}}/exe` and `ls -ld /proc/{{firstPid}}/cwd`
4. Review open sockets and files: `ss -p | grep {{firstPid}}` and `lsof -p {{firstPid}}`
5. Compare the process against expected application workers, maintenance scripts, or package-managed services.

**Backup commands:**
1. Capture process maps: `cat /proc/{{firstPid}}/maps > /tmp/proc-{{firstPid}}-maps-$(date +%s).txt`
2. Record process status and cmdline: `cat /proc/{{firstPid}}/status > /tmp/proc-{{firstPid}}-status-$(date +%s).txt`; `cat /proc/{{firstPid}}/cmdline | tr '\0' ' ' > /tmp/proc-{{firstPid}}-cmdline-$(date +%s).txt`

**Suggested next action:**
1. Treat this as high-priority runtime triage. Do not kill the process until you capture enough context for investigation.
2. Identify the owning service, script path, parent process, and network activity.
3. If unexpected, preserve memory or process artifacts, then terminate the interpreter process.
4. Review parent service logs and deployment history for injected `-c`, eval, plugin, or native extension payloads.

**Rollback commands:**
1. If a legitimate worker was stopped, restart the owning service through the normal service manager: `systemctl restart <service>`
2. Re-run the process runtime check and confirm the RWX mapping is gone or understood.

**Risk level:** CRITICAL

**Confidence / caveat:** High confidence when the interpreter process is unexpected or network-connected. Some JIT, debugger, profiler, or native-extension workflows may briefly create RWX pages; validate against the application's normal runtime behavior.

## Metadata Reference

The following metadata fields may be present in rule results:

- `mapsTruncated` — `"true"` when at least one process had `/proc/<pid>/maps` exceed the 512 KB read cap. If present, the rule may have missed RWX regions in truncated processes.
- `environTruncated` — `"true"` when at least one process had `/proc/<pid>/environ` exceed the 256 KB read cap. If present, the rule may have missed `LD_PRELOAD` or `LD_AUDIT` variables in truncated processes.
- `mapsUnreadableCount` — Number of process map files that could not be read. If present on a pass, the rule only cleared the readable subset.
- `environUnreadableCount` — Number of process environment files that could not be read. If present on a pass, dynamic-linker injection may be hidden in unreadable process environments.
- `exeUnreadableCount` — Number of process executable symlinks that could not be resolved. If present on a pass, deleted-binary or temp-path execution may be hidden in unreadable process executable paths.
- `missingParentCount` — (PROC-005 only) Number of processes whose parent PID was not present in the snapshot. High values may indicate heavy process churn, namespace boundaries, or daemonize-and-die evasion.
- `totalChecked` — (PROC-005 only) Number of processes with a valid parent PID (> 0) that were evaluated for suspicious relationships.

> These are suggestions only. Review commands before running them on your system.
