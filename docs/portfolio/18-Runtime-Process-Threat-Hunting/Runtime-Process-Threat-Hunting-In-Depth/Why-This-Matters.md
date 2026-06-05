# Why Runtime Process Threat Hunting Matters

> Static configuration audits tell you what the system *should* look like. Runtime process inspection tells you what the system *actually* looks like right now.

---

## The Gap

Traditional security posture tools audit configuration files: SSH settings, firewall rules, file permissions, cron entries. These are essential, but they share a blind spot — **they cannot see what is already running in memory**.

An attacker who has gained a foothold can:

1. Drop a payload to `/dev/shm`, execute it, and delete the original file
2. Inject shellcode into a running process via `/proc/<pid>/mem` or `ptrace`
3. Set `LD_PRELOAD` to hook library calls for credential harvesting
4. Spawn a reverse shell from a compromised web server
5. Daemonize a backdoor so it parents itself to `init` with a random name

None of these activities leave persistent configuration changes. A cron table will look clean. SSH config will look clean. File permissions will look clean. The only evidence is in the live process table.

---

## What Live /proc Data Provides

The Linux kernel exposes every running process through `/proc/<pid>/`. For DFIR, the most valuable files are:

| File | What It Reveals |
|---|---|
| `/proc/<pid>/maps` | Memory regions, permissions, and mapped files — shows RWX injection, shared libraries, and mapped paths |
| `/proc/<pid>/environ` | Environment variables — shows `LD_PRELOAD`, `LD_AUDIT`, and other linker hijacking signals |
| `/proc/<pid>/exe` | Symlink to the actual executable — shows `(deleted)` binaries and temp-path execution |
| `/proc/<pid>/cmdline` | Full command line — shows encoded payloads, suspicious arguments, and interpreter invocations |
| `/proc/<pid>/status` | PPid, Uid, Name, State — shows parent-child relationships and orphaned processes |
| `/proc/<pid>/comm` | Short process name — confirms identity when `status.Name` is ambiguous |

---

## Why This Is Different From Other Agent Scanners

Most Security Agent scanners read configuration files or run commands that return configuration state:

- `FirewallScanner` reads `iptables -L` output
- `SshConfigScanner` reads `sshd -T` output
- `KernelHardeningScanner` reads `/proc/sys/*` sysctl values

`ProcessRuntimeScanner` is the only scanner that inspects **mutable runtime state**. The data changes every millisecond. A process that exists during the scan may exit before the analyst reads the result. This ephemerality is exactly why the scanner must be fast, concurrent, and resilient — it is racing against process death.

---

## The "Visible Shift" Value

The original VulcansTrace value proposition was log analysis and configuration auditing. Adding runtime process threat hunting visibly shifts the tool from **posture assessment** to **DFIR readiness**:

- A SOC analyst can now ask "check my processes" and receive injection, persistence, and RCE indicators
- An incident responder can run a single command and get a snapshot of all running processes with anomaly flags
- A compliance auditor can see not just "SSH is hardened" but also "no web server is currently spawning shells"
- The tool can detect anti-forensics techniques (deleted binaries, memory injection) that evade file-based detection

---

## Security Principles Behind the Design

1. **Complement, don't duplicate** — The scanner does not replace YARA, file integrity monitoring, or EDR. It adds a lightweight, local, deterministic layer that works without third-party dependencies or kernel modules.

2. **Fail open, signal failure** — When `/proc` files are unreadable, the scanner returns partial data and marks truncation/permission status explicitly. A rule that sees `environTruncated=true` knows it may have missed an `LD_PRELOAD` variable.

3. **Bounded by design** — Memory caps, concurrency limits, and per-file isolation ensure the scanner does not harm the system it is inspecting. This is critical for production deployments.

4. **Deterministic and testable** — Every rule has explicit pass/fail/NotApplicable logic with no statistical scoring. The behavior is fully reproducible given the same `/proc` snapshot.

---

## Business Value

- **No additional licenses** — Uses only `/proc`, `readlink`, and standard .NET async I/O
- **No kernel modules** — Does not require LKM installation, eBPF, or ptrace privileges
- **Fast** — Bounded concurrency scans all processes in seconds on typical Linux hosts
- **Portable** — Works on any Linux system with `/proc` (virtually all modern distributions)
- **Integrable** — Findings flow through the same `Finding`, `AnalysisResult`, and evidence pipeline as all other agent rules