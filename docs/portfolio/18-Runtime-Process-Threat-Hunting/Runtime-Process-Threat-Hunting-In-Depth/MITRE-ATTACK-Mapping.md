# MITRE ATT&CK Mapping: Runtime Process Threat Hunting

## Technique Coverage

| Rule | Technique | Tactic | Why It Matters |
|---|---|---|---|
| PROC-001 | T1055 — Process Injection | Defense Evasion | RWX memory regions are the primary observable indicator of code injection, reflective loading, and position-independent shellcode |
| PROC-001 | T1620 — Reflective Code Loading | Defense Evasion | Malware that loads itself into memory without touching disk allocates RWX pages to stage and execute payloads |
| PROC-002 | T1574.006 — Dynamic Linker Hijacking | Persistence, Privilege Escalation | `LD_PRELOAD` and `LD_AUDIT` force the dynamic linker to load attacker-controlled libraries before all others, enabling function hooking and credential harvesting |
| PROC-003 | T1036 — Masquerading | Defense Evasion | Execution from `/tmp`, `/var/tmp`, or `/dev/shm` and `(deleted)` binaries are classic masquerading techniques to evade file-based detection |
| PROC-003 | T1105 — Ingress Tool Transfer | Command and Control | Attackers frequently drop tools to temporary paths before execution; detecting temp-path execution catches the transfer-to-execution transition |
| PROC-004 | T1036 — Masquerading | Defense Evasion | Randomly generated alphanumeric process names parented to `init` are a hallmark of daemonized malware attempting to blend in with system processes |
| PROC-005 | T1059 — Command and Scripting Interpreter | Execution | Network services spawning interpreters is the observable result of successful remote code execution, webshells, and SQL injection with shell access |
| PROC-006 | T1055 — Process Injection | Defense Evasion | Interpreter processes with RWX memory are a high-signal form of in-process payload staging |
| PROC-006 | T1620 — Reflective Code Loading | Defense Evasion | Reflectively loaded payloads in scripting runtimes can surface as executable writable regions |
| PROC-006 | T1059 — Command and Scripting Interpreter | Execution | RWX memory in python/perl/ruby/php adds runtime evidence to command-interpreter execution |

---

## Attack Lifecycle Context

### Reconnaissance → Initial Access → Execution

The rules do not directly detect reconnaissance or initial access. They detect the **execution** and **persistence** stages that follow successful compromise.

| Stage | Typical Observable | Matching Rule |
|---|---|---|
| Initial Access | Web exploitation, SSH brute force, phishing | Not directly detected |
| Execution | Web server spawns shell/interpreter | **PROC-005** |
| Execution | Interpreter process maintains RWX memory | **PROC-006** |
| Execution | Dropped payload runs from `/tmp` or `/dev/shm` | **PROC-003** |
| Persistence | `LD_PRELOAD` hook installed | **PROC-002** |
| Defense Evasion | Binary deleted while running | **PROC-003** |
| Defense Evasion | Process injected with shellcode | **PROC-001** |
| Defense Evasion | Daemonized with random name under init | **PROC-004** |

---

## Why These Techniques

### T1055 + T1620 — Process Injection / Reflective Code Loading

Modern exploit frameworks (Metasploit, Cobalt Strike, Sliver) frequently allocate RWX pages in target processes. Linux legitimate processes rarely maintain RWX regions in steady state — JIT compilers (Java, .NET) typically transition to RX after startup. PROC-001 treats RWX as strongly suspicious with Critical severity, while PROC-006 highlights the especially important interpreter-process subset.

### T1574.006 — Dynamic Linker Hijacking

`LD_PRELOAD` is a first-class Linux persistence technique documented in MITRE ATT&CK. It is used by rootkits (e.g., azazel, vlany), credential harvesters, and red-team tools. Because it lives in environment variables, it is invisible to file-integrity monitoring and YARA file scanning. PROC-002 is the only agent rule that inspects process environments.

### T1036 — Masquerading

MITRE defines masquerading as "matching names or locations of legitimate files or resources." In Linux, this manifests as:
- Execution from paths that look temporary or benign (`/tmp`, `/dev/shm`)
- Deleting the original binary while still running (`(deleted)` suffix)
- Random process names that mimic system daemons

PROC-003 and PROC-004 both address masquerading from different angles.

### T1105 — Ingress Tool Transfer

While T1105 is typically associated with network-based tool transfer (SCP, FTP, HTTP download), the **execution phase** of tool transfer is detectable via PROC-003. A payload that was transferred to `/dev/shm` and is now executing is the observable bridge between transfer and execution.

### T1059 — Command and Scripting Interpreter

MITRE T1059 covers the execution of commands through interpreters (bash, python, PowerShell). PROC-005 detects this specifically in the context of **unexpected parent processes** — a web server spawning `python3` is not normal operation and indicates that some other exploit mechanism has already succeeded. PROC-006 adds a runtime-memory view of the same technique family by flagging interpreter processes that maintain RWX mappings.

---

## Navigator Layer Integration

The VulcansTrace evidence pipeline includes `MitreLayerBuilder`, which produces MITRE ATT&CK Navigator v4.5-compatible layer JSON. Process runtime findings contribute to the layer through their `RuleResult.MitreTechniques` mappings.

When PROC-001 fires, the layer receives:
- Technique T1055 (score += 1)
- Technique T1620 (score += 1)

When PROC-002 fires:
- Technique T1574.006 (score += 1)

When PROC-003 fires:
- Technique T1036 (score += 1)
- Technique T1105 (score += 1)

When PROC-004 fires:
- Technique T1036 (score += 1)

When PROC-005 fires:
- Technique T1059 (score += 1)

When PROC-006 fires:
- Technique T1055 (score += 1)
- Technique T1620 (score += 1)
- Technique T1059 (score += 1)

Scores are aggregated deterministically and rendered as gradient-colored technique cells in the Navigator layer.

---

## Gap Analysis

| MITRE Technique | Covered By | Gap |
|---|---|---|
| T1055 — Process Injection | PROC-001, PROC-006 | Thread-level injection without distinct maps entries may evade |
| T1059.004 — Unix Shell | PROC-005, PROC-006 | PROC-005 only detects specific parents; PROC-006 focuses on interpreter RWX memory, not every interpreter process |
| T1543 — Create or Modify System Process | Not covered | Systemd unit persistence requires configuration audit, not runtime inspection |
| T1547 — Boot or Logon Autostart Execution | Not covered | Requires cron, systemd, or init file inspection (covered by other agent rules) |
| T1564 — Hide Artifacts | Partial (PROC-003, PROC-004) | Memory-only artifacts (no maps entries) are invisible |

---

## Security Takeaways

1. The six rules cover the execution, persistence, and defense-evasion phases of the MITRE ATT&CK framework
2. No single rule is sufficient — a mature attack will often trigger multiple rules (e.g., PROC-005 for RCE + PROC-003 for deleted binary + PROC-002 for LD_PRELOAD persistence)
3. The Navigator layer integration turns individual findings into visual threat-intelligence overlays
4. Gap areas (systemd persistence, boot autostart) are covered by other agent rule families, not process runtime
5. Thread-level injection and memory-only artifacts remain theoretical gaps for future improvement
