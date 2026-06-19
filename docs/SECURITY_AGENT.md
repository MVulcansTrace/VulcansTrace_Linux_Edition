# Security Agent

The Security Agent is a local, rule-based Linux security assistant built into VulcansTrace Linux Edition. It answers plain-English security questions, scans live host state, evaluates defensive posture rules, explains findings, and can include pasted firewall logs in the same analysis workflow.

The agent is intentionally deterministic. It does not call an external LLM or send system data to a service. Its value comes from a predictable pipeline: query parsing, local scanners, rule evaluation, explanation templates, and compatibility with the existing VulcansTrace `AnalysisResult` and evidence pipeline.

The agent is also **conversation-aware**: it tracks the current topic, last intent, resolved entities, and recent dialogue turns so follow-ups like `fix it`, `verify it`, and `only the SSH ones` are resolved without forcing the user to repeat rule IDs or categories.

## What It Can Answer

The query parser maps natural-language prompts to structured intents:

| Example prompt | Intent | Result |
| --- | --- | --- |
| `Is my system secure?` | `FullAudit` | Runs all agent rule categories |
| `Run a full audit` | `FullAudit` | Runs all agent rule categories |
| `Check my firewall` | `FirewallCheck` | Runs firewall posture rules |
| `How's my iptables?` | `FirewallCheck` | Runs firewall posture rules |
| `What ports are open?` | `PortCheck` | Reviews listening ports and exposure |
| `What services are running?` | `ServiceCheck` | Reviews running services |
| `Who am I talking to?` | `NetworkCheck` | Reviews routes, interfaces, and connections |
| `Check my SSH` | `SshCheck` | Reviews SSH daemon hardening configuration |
| `Check my ssh service` | `SshCheck` | Specific keywords take precedence over generic ones (`service`) |
| `Check file permissions` | `FilePermissionCheck` | Reviews sensitive file and directory permissions |
| `Check my filesystem` | `FilesystemAuditCheck` | Reviews world-writable files, SUID/SGID binaries, unowned files, sticky-bit checks, and /tmp mount hardening |
| `Check my kernel hardening` | `KernelCheck` | Reviews kernel and system hardening parameters |
| `Check my user accounts` | `UserAccountCheck` | Reviews user accounts, password aging, PAM complexity, and shadow entries |
| `Check my logging` | `LoggingAuditCheck` | Reviews rsyslog, journald, auditd, logrotate, and central forwarding configuration |
| `Check my cron jobs` | `CronJobCheck` | Reviews cron entries for suspicious commands, world-writable scripts, and root jobs referencing user paths |
| `Check package vulnerabilities` | `PackageVulnerabilityCheck` | Reviews installed packages for pending security updates and known CVEs |
| `Check my containers` | `ContainerCheck` | Reviews container runtime posture (privileged mode, latest tags, Docker socket exposure/mounts, risky base-image hints, namespace isolation) |
| `Check my kubernetes` | `KubernetesCheck` | Reviews Kubernetes pod security posture (privileged pods, host namespaces, root containers, security contexts) |
| `Check my pods` | `KubernetesCheck` | Alias for Kubernetes pod security audit |
| `Check my processes` | `ProcessRuntimeCheck` | Reviews live process state for injection, persistence, and anti-forensics indicators |
| `Check running processes` | `ProcessRuntimeCheck` | Alias for runtime process threat hunting |
| `Check process runtime` | `ProcessRuntimeCheck` | Alias for runtime process threat hunting |
| `Check threat intel` | `ThreatIntelCheck` | Correlates active connections, open ports, and file hashes against imported STIX/MISP IOCs |
| `Check malicious IPs` | `ThreatIntelCheck` | Alias for threat intel correlation |
| `Run a YARA scan` | `YaraCheck` | Scans SUID/SGID binaries, running process executables, and cron scripts against bundled and custom YARA rules |
| `Check for malware signatures` | `YaraCheck` | Alias for YARA signature scan |
| `Explain FW-001` | `ExplainFinding` | Explains a cached finding by rule ID, or runs that single rule if needed |
| `Explain this finding` | `ExplainFinding` | Explains the currently selected UI finding when one is selected |
| `What changed since the last audit?` | `ShowChanges` | Diff the current audit against the previous history entry |
| `Why is this critical?` | `ExplainCritical` | Explain only Critical/High findings from the last audit |
| `Show only firewall issues` | `FilterCategory` | Filter the last audit's findings by category (falls back to a fresh category audit when no context exists) |
| `What should I fix first?` | `PrioritizeRemediation` | Build a severity-ordered remediation plan from the last audit |
| `Fix FW-001` | `FixFinding` | Show a single-finding remediation preview when rollback guidance is present. No session or timeline is created. |
| `Remediate FW-001` | `StartRemediation` | Start a persisted guided remediation session with step state, before snapshot, and an immutable event timeline |
| `Verify remediation abc12345` | `VerifyRemediation` | Re-run the session's audit intent and produce a before/after remediation diff. Adds `VerificationStarted` plus a terminal `VerificationCompleted`, `VerificationBlocked`, or `VerificationFailed` event to the session timeline |
| `List my sessions` / `Show sessions` | `ListRemediationSessions` | List all persisted remediation sessions with ID, status, rule ID, and creation time |
| `Resume session abc12345` | `ResumeRemediation` | Reload a previously saved remediation session into the chat panel for review or continued verification |
| `Add note to session abc12345 <text>` | `AddSessionNote` | Append a free-text note to an existing remediation session |
| `Note for step FW-001 in session abc12345 <text>` | `AddStepNote` | Append a note to a specific remediation step within a session |
| `Which findings are suppressed?` | `ListSuppressed` | List suppressed findings from the last audit |
| `Set baseline` | `SetBaseline` | Save the last audit as a known-good baseline snapshot |
| `Check drift` | `CheckDrift` | Compare live config against the saved baseline and report new/worsened findings |
| `Show baseline` | `ShowBaseline` | Display the active baseline findings for the last audit intent |
| `What's my risk grade?` | `RiskScore` | Returns the aggregate risk scorecard after an audit |
| `Help` | `Help` | Returns supported agent capabilities |
| `Fix it` (after explaining a finding) | `FixFinding` | Resolves `it` to the last explained finding and shows the interactive remediation preview |
| `Remediate it` (after explaining a finding) | `StartRemediation` | Resolves `it` to the last explained finding and starts a guided remediation session |
| `Verify it` (after remediation) | `VerifyRemediation` | Resolves `it` to the active remediation session and re-runs the original audit intent |
| `Explain it` (after explaining a finding) | `ExplainFinding` | Resolves `it` to the last explained finding and re-explains it |
| `Explain the second one` (after an audit) | `ExplainFinding` | Resolves the ordinal to the second ranked finding from the last audit |
| `Only the SSH ones` (after an audit) | `FilterCategory` | Resolves `SSH ones` to the SSH category and filters the last audit |
| `What should I fix first?` | `PrioritizeRemediation` | Build a severity-ordered remediation plan from the last audit |

## Conversation Awareness

The Security Agent keeps a lightweight, deterministic dialogue context so multi-turn questions work without an LLM:

- **Topic tracking** — each turn updates the conversation topic (`Unknown`, `Audit`, `Explanation`, `Remediation`, `Help`, `Comparison`, `Drift`). The topic gates which inferences are safe to apply; every non-audit/non-baseline intent is mapped to a topic via `DialogueContext.TopicForIntent`.
- **Entity tracking** — the context remembers the last rule ID, category, remediation session ID, ordinal selection, focused finding, and ranked findings from the last audit.
- **Anaphora resolution** — pronouns (`it`, `that`, `this one`) and ordinals (`the first one`, `the second finding`) are resolved against the context. Ordinals are deliberately treated as direct references, not anaphora, so `what should I fix first` is still interpreted as prioritization. Session references (`verify it`, `check it`) only resolve to a session when the conversation is already in a remediation context or a session exists.
- **Intent inference** — when the keyword parser is uncertain or the query is context-dependent, a deterministic inference engine maps `(prior topic, resolved entities, raw query)` to the most likely intent. For example, after an explanation topic, `fix it` becomes `FixFinding`; after a remediation topic, `verify it` becomes `VerifyRemediation`.
- **Target building** — `IntentInferenceEngine.BuildTarget` combines resolved references with parser output and entity-frame fallbacks, giving precedence to explicitly resolved values so a remediation session ID is never overwritten by the last rule ID.
- **Snapshot isolation** — `DialogueManager.Resolve` snapshots the `EntityFrame` under the context lock before handing it to the resolver and inference engine. `SecurityAgent` reads from that snapshot; context mutations happen after the turn result is produced.
- **Save/restore integrity** — follow-up services that run nested audits (`CheckDrift`, verification, category-filter fallback) use `DialogueContext.SnapshotState`/`RestoreState` to capture and restore the full entity frame, preventing transient audits from leaking `RankedFindings`, focused finding, or category state.
- **Clarification prompts** — if a query remains genuinely ambiguous, the agent asks a deterministic clarification question instead of guessing.

All inference is rule-based and testable. The context lives in `DialogueContext` and is persisted in memory per `SecurityAgent` instance; it is not sent to any external service.

### Cross-Session Memory

The agent persists a lightweight conversation-memory snapshot so it can resume context after the application restarts:

- **What is saved** — last intent/topic, last audit intent, focused rule ID and category, active/last remediation session ID, the most recent 20 dialogue turns, a per-rule `RuleHistory` snapshot, and a reference to the latest audit-history snapshot.
- **What is not saved** — full findings are not duplicated. The snapshot references the existing `IAuditHistoryStore` entry and rehydrates a synthetic `AgentResult` from its `SnapshotFindings` on startup. The rehydrated result now also restores the original `CapabilityReport`, `RuleResults`, `Warnings`, and `LogAnalysisResult`; `RemediationPlan` and `RemediationSession` are not duplicated because they have their own persistence stores.
- **Where it lives** — `JsonFileAgentMemoryStore` writes atomically to `~/.config/VulcansTrace/agent-memory.json` (temp file + rename) with an in-memory fallback if the filesystem is unavailable. Saves use async file I/O and are awaited before the result is returned so the restored context matches the last completed agent action.
- **When it loads/restores** — `SecurityAgent` loads the snapshot on construction, restores the `EntityFrame` and recent history, and rehydrates `LastResult` from audit history. If the referenced history entry is missing, the focus fields are cleared to avoid half-restored state. Snapshots older than 90 days are ignored. Corrupt or missing fields in `SnapshotFindings` are replaced with safe defaults so startup cannot crash on bad JSON.
- **When it saves** — after completed query, audit, explanation, baseline, remediation, and session-management actions, the current entity frame and history are snapshotted and persisted. A throwing custom store does not discard the result already returned to the caller.
- **Warning surfacing** — `JsonFileAgentMemoryStore.PersistenceWarning` is surfaced in the Avalonia UI as an info message, like the warnings from other stores.

This makes follow-ups like `"what should I fix first?"`, `"fix it"`, and explicit references like `"explain TEST-001"` work immediately after reopening the application, as long as the audit history store still contains the referenced snapshot.

### Per-Rule Memory and Trend Tracking

In addition to conversation context, the agent keeps a lightweight per-rule memory store:

- **What is tracked** — for every rule that has failed at least once, a `RuleMemoryEntry` records `FirstSeenUtc`, `LastSeenUtc`, `LastRemediationAttemptUtc`, `LastVerifiedFixedUtc`, a rolling list of `RuleSeveritySnapshot` records, and a deterministic `RuleStatusTrend` (`New`, `Stable`, `Improving`, `Worsening`).
- **How it is recorded** — `RuleMemoryRecorder` is invoked after each audit. Findings are grouped by `RuleId` and one snapshot is written per rule using the worst severity observed in that audit, so repeated targets do not create duplicate history entries. `LastRemediationAttemptUtc` is stamped only after observable remediation progress: a guided session step is marked in progress, completed, or failed, or a live CLI auto-fix actually executes an apply command. Creating a plan or session alone does not count as an attempt.
- **How it is used** — the narrative composer references memory to explain whether an issue is new, recurring, improving, or worsening, and now also surfaces remediation attempts and verified-fixed timestamps; the suggestion provider uses it to recommend stale or worsening findings for attention; `VerifyFindingAsync` stamps `LastVerifiedFixedUtc` when the finding is no longer present.
- **Where it lives** — rule history is serialized inside the same `agent-memory.json` snapshot and restored on startup. It is not sent to any external service.

### Frame-Based Entity Extraction

The parser extracts a structured `QueryEntityFrame` from free text before intent inference runs:

| Entity | Example matches | Used for |
| --- | --- | --- |
| Rule IDs | `FW-001`, `SSH-003`, `PORT-002` | Targeted explanations, remediation, and verification |
| Categories | `firewall`, `ssh`, `filesystem` | Category filtering and follow-up inference |
| Session IDs | `abc12345`, `deadbeef` | Session notes, resume, and verification |
| Severity filters | `critical`, `high`, `medium` | Result filtering and prioritization |
| Time windows | `last 7 days`, `this week` | Potential future time-scoped queries |
| Remediation verbs | `fix`, `remediate`, `verify` | Disambiguating intent when keywords overlap |
| Ordinals | `the first one`, `the second finding` | Resolving references against ranked findings |

Extraction is deterministic, uses word-boundary regex matching, and runs in `EntityExtractor`. The extracted frame is merged with parser output and anaphora resolution before `IntentInferenceEngine` selects the final intent.

### Posture Correlation

The agent can surface posture correlations: pairs of rule failures that together represent a higher-risk condition than either finding alone. Correlations are produced by `PostureCorrelator` and rendered in the narrative and evidence exports:

| Pattern | Meaning |
| --- | --- |
| `FW-002 + SSH-002` | An SSH port is open and the firewall does not explicitly allow it, or password authentication is enabled without firewall coverage. |
| `FW-004 + PORT-*` | Firewall tooling is missing while listening ports are exposed. |
| `USER-001 + SSH-002` | Multiple UID-0 accounts exist and password SSH authentication is enabled. |

Correlations are deduplicated by `(PatternId, RuleIdA, RuleIdB)` within a result, and the narrative paragraph always cites both rule IDs so the claim is traceable to the underlying findings.

### Narrative Composition

Agent replies are composed as multi-paragraph prose by `NarrativeComposer`:

- **Summary paragraph** — high-level audit outcome and total counts.
- **Key findings paragraph** — a compact list of the highest-severity findings, citing rule IDs, severity, and what was observed.
- **Correlation paragraph** — lists any posture correlations with both rule IDs.
- **Memory paragraph** — highlights repeated, improving, or worsening issues using per-rule memory.
- **Traceability invariant** — every non-generic paragraph cites source IDs (rule IDs, finding fingerprints, or correlation keys) in its rendered text. `Narrative.SourceIds` collects these IDs and is validated by automated tests.

The composed `AgentResult.Narrative` is rendered in the Avalonia chat panel (with `**bold**` and `*italic*` styling via `MarkdownInlinesConverter`), stripped of markdown in the CLI, and included in evidence exports as `agent-narrative.md`. Posture correlations are exported as `posture-correlations.md` when present.

## Follow-Up Suggestions

Every agent reply now includes a small set of contextual follow-up suggestions. They are generated deterministically by `AgentSuggestionProvider` from the current `AgentResult` and `EntityFrame`, with no external LLM:

| Result state | Example suggestions |
| --- | --- |
| Audit with Critical/High findings | `What should I fix first?`, `Why is this critical?`, `Show only <category> issues`, `Explain <top-rule>`, `What's my risk grade?` |
| Audit with posture correlations | `Fix <rule-a> and <rule-b> together` |
| Audit with current stale or worsening finding | `Prioritize <rule> — is still open`, `Prioritize <rule> — is worsening` |
| Audit with no findings | `Set baseline`, `Check another area`, `Run a full audit` (after a targeted audit) |
| After explaining a finding | `Fix it`, `Remediate it`, `Show related <category> findings`, `What should I fix first?` |
| After starting/resuming remediation | `Verify session`, `Add a note`, `List sessions` |
| After `PrioritizeRemediation` | `Fix <first-rule>`, `Show all findings`, `What's my risk grade?` |
| After verifying a finding | related current-finding suggestions, including correlated follow-ups when applicable |
| After `SetBaseline` | `Check drift` |
| After `CheckDrift` | `Show baseline`, `Update baseline` |
| After `RiskScore` | `Show only <top-category> issues`, `What should I fix first?` |

In the Avalonia UI, suggestions appear as clickable chips below the agent message they belong to. Clicking a chip executes the suggestion using its `Intent`: audit-intent suggestions call `RunAuditAsync` directly, while all other suggestions fall back to the natural-language query path. This guarantees that chips such as **Show all findings** route to the correct audit intent instead of being re-parsed and misrouted. The CLI and JSON output include suggestions as structured data but do not render interactive chips.

## Verify Loop

The agent can verify whether an individual finding is still present without starting a full remediation session:

- **API** — `SecurityAgent.VerifyFindingAsync(ruleId, ct)` re-runs the last audit intent and checks whether a finding with the requested rule ID appears in the new result.
- **Memory update** — if the finding is no longer present, `RuleMemoryRecorder.MarkVerifiedFixed` stamps `LastVerifiedFixedUtc` for that rule. The updated rule history is saved to the cross-session memory snapshot. If the rule later reappears, the continuity paragraph will note that it was previously verified fixed.
- **Narrative** — the result includes a short narrative explaining whether the finding is fixed, still present, or not found in the current context.
- **Suggestions** — after verification, suggestions are generated from the current re-audit result, including related correlated findings when applicable.

This is useful for quick one-off checks after applying a manual fix: call `VerifyFindingAsync("FW-001")` and the agent reports the current status while keeping the rule-memory timeline accurate.

## Session Timeline

Guided remediation sessions (`remediate <finding>`) record an immutable event timeline for audit traceability:

- **Created** — recorded when the session starts.
- **StepMarkedPending / StepMarkedInProgress / StepMarkedCompleted / StepMarkedSkipped / StepMarkedFailed** — recorded when a step state changes.
- **StepBlocked** — recorded for each blocked section at session creation.
- **VerificationStarted** — recorded before the verification audit runs.
- **VerificationCompleted** — recorded after the before/after diff is built, with counts of fixed/unchanged/new/worsened findings.
- **VerificationBlocked** — recorded when verification is refused due to a missing before snapshot or a blocked session status.
- **VerificationFailed** — recorded when the verification audit crashes after verification has started.
- **Exported** — recorded only after **Export Session** successfully writes the markdown report. Cancelled or failed saves do not mutate the timeline.
- **SessionResumed** — recorded when a session is loaded back into the UI via `ResumeRemediation` or the **Resume** button.
- **SessionNoteAdded** — recorded when a session-level note is appended via `AddSessionNote`.
- **StepNoteAdded** — recorded when a step-level note is appended via `AddStepNote`.

The timeline is visible in the Avalonia chat UI under the session card and is included in exported session markdown reports under a `## Timeline` section. After a successful export, the UI refreshes the current session timeline so the persisted `Exported` event is visible in chat.

## Session Notes

Remediation sessions support free-text notes for audit traceability:

- **Session notes** — attached to the session itself (`AddSessionNote`). Use these for general observations, handoff context, or runbook references.
- **Step notes** — attached to a specific remediation step (`AddStepNote`). Use these for per-step observations, troubleshooting notes, or evidence links.

Notes are append-only and immutable. Each note records:
- `Text` — the note content (evidence syntax is stripped from the stored text).
- `CreatedAtUtc` — UTC timestamp when the note was added.
- `RuleId` — `null` for session notes; the step's rule ID for step notes.
- `EvidenceLinks` — a list of evidence references extracted from bracket or backtick syntax in the note text.

### Evidence Syntax in Notes

When typing a note, you can reference evidence using two lightweight syntaxes:

- **Bracket syntax**: `[evidence-reference]` — e.g., `[screenshot-2026-06-02]` or `[ticket-SEC-12345]`
- **Backtick syntax**: `` `evidence-reference` `` — e.g., `` `audit-log-2026-06-02` ``

Both syntaxes are automatically extracted into the note's `EvidenceLinks` list and stripped from the displayed text. This keeps the note readable while preserving traceable references. The syntax is stripped on both session notes and step notes, and on both the `AddSessionNote`/`AddStepNote` intents and the `SessionNoteAdded`/`StepNoteAdded` timeline events.

### Note Intents and Routing

`SecurityAgent.AskAsync` routes note intents through `GuidedRemediationService`:

- `AddSessionNote` — extracts the session ID from the query, validates the session exists, appends a `SessionNoteAdded` timeline event, and returns a concise confirmation.
- `AddStepNote` — extracts both the rule ID and session ID, validates the session and step exist, appends a `StepNoteAdded` timeline event, and returns a concise confirmation.

If the referenced session does not exist, the step does not exist, or the step rule ID is empty, the agent returns a guidance message instead of modifying the session.

### Notes in Session Exports

The `RemediationMarkdownFormatter` renders notes under a dedicated `## Notes` section in exported session reports:

- Session notes are grouped under `### Session Notes`.
- Step notes are grouped under `### Step Notes`, organized by rule ID.
- Each note shows its timestamp, text, and any evidence links as a bulleted list.

Notes appear after the Timeline section and before Blocked Steps in the exported markdown.

## Doctor — Data-Source Self-Diagnostic

Before running an audit, you can verify which scanner data sources are reachable on the current host:

```bash
vulcanstrace doctor
```

The Doctor runs every scanner in read-only probe mode, collects normalized `DataSourceCapability` records, and emits the same deterministic capability report used during audits. It does **not** evaluate rules or modify the system. The Avalonia UI exposes the same capability probe on a dedicated **Doctor** tab, with a summary status banner and a warnings banner for scanner command failures or permission limits.

Use this to confirm visibility before interpreting audit results — for example, if `iptables` or `ss` require elevated privileges to return full output, the Doctor will report `PermissionLimited` rather than `Available`.

## Data Sources

The agent reads local host state using common Linux tools:

| Scanner | Commands | Purpose |
| --- | --- | --- |
| `FirewallScanner` | `iptables -L -n -v`, fallback `nft list ruleset` | Reads firewall posture and rule text |
| `PortScanner` | `ss -tulnp`, fallback `netstat -tulnp` | Finds listening TCP/UDP ports and owning processes when visible |
| `ServiceScanner` | `systemctl list-units --type=service --state=running --no-pager --no-legend` | Finds running systemd services |
| `NetworkScanner` | `ip addr`, `ip route`, `ss -tunap` | Reads interfaces, routes, and active connections |
| `SshConfigScanner` | `sshd -T`, fallback `/etc/ssh/sshd_config` + includes | Reads SSH daemon hardening directives |
| `FilePermissionScanner` | `stat -c '%a %U %G %n'` | Reads permission bits, ownership, and existence of sensitive files and directories |
| `FilesystemAuditScanner` | `find / -xdev … -exec stat …` | Discovers world-writable files, SUID/SGID binaries, unowned files, world-writable dirs without sticky bit, and /tmp mount options |
| `KernelHardeningScanner` | `/proc/sys/*` direct reads, fallback `sysctl -a`, `mokutil --sb-state` | Reads kernel parameters (ASLR, IP forwarding, ICMP redirects, source routing, module loading, pointer exposure) and Secure Boot status |
| `UserAccountScanner` | `/etc/passwd`, `/etc/shadow`, `/etc/login.defs`, PAM password-stack configs (`common-password`, `system-auth`, `password-auth`), PAM auth-stack configs (`common-auth`, `/etc/pam.d/sshd`), `/etc/security/pwquality.conf`, `/etc/security/faillock.conf` | Reads local user accounts, shadow entries, password aging policy, PAM password-stack and auth-stack configuration, and faillock settings |
| `LoggingAuditScanner` | `systemctl is-active rsyslog journald auditd`, `auditctl -l`, `/etc/audit/audit.rules`, `/etc/logrotate.conf`, `/etc/rsyslog.conf`, `/etc/rsyslog.d/*.conf`, `/etc/systemd/journald.conf` | Checks logging service status, auditd rules, logrotate configuration, and central forwarding targets |
| `CronJobScanner` | Reads `/etc/crontab`, `/etc/cron.d/*`, `/var/spool/cron/crontabs/*`, `/var/spool/cron/*`, `/etc/cron.daily/*`, `/etc/cron.hourly/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`; uses `stat` for script permissions | Parses system and user crontabs and cron script directories for scheduled job entries and script permissions |
| `PackageVulnerabilityScanner` | `dpkg-query -W`, `apt list --upgradeable`, `apt-cache policy`, optionally `debsecan --format report --only-fixed`, `/etc/apt/apt.conf.d/50unattended-upgrades`, `/etc/apt/apt.conf.d/20auto-upgrades` | Enumerates installed packages, detects pending security updates from security repositories, enriches with CVE IDs when debsecan is available, and checks unattended-upgrades configuration |
| `ContainerScanner` | `docker ps`, `docker inspect`, `crictl ps`, `ctr namespace ls` | Detects running containers, privileged mode, latest tags, Docker socket exposure/mounts, known risky base-image hints from local image metadata, and containerd namespace isolation |
| `KubernetesScanner` | `kubectl get pods --all-namespaces -o json` | Detects Kubernetes pod security posture when kubeconfig is present; supports `$KUBECONFIG` env var and uses the configured cluster context |
| `YaraScanner` | `find / -xdev …`, `/proc/<pid>/exe` resolution, reads `/etc/cron.d*/*`; uses `libyara` via a thin P/Invoke wrapper | Scans SUID/SGID binaries, running process executables, and cron scripts against bundled rules (`Scanners/Yara/Rules/bundled.yar`) plus optional custom rules in `~/.config/VulcansTrace/yara/*.yar` |
| `ProcessRuntimeScanner` | `/proc/<pid>/status`, `/proc/<pid>/comm`, `readlink /proc/<pid>/exe`, `/proc/<pid>/cmdline`, `/proc/<pid>/maps`, `/proc/<pid>/environ` | Reads live process state: memory maps, environment variables, executable paths, command lines, and parent-child relationships with bounded concurrency and per-file fault isolation |

Scanner failures are reported as warnings instead of crashing the agent. Scanner commands use a shared bounded runner with concurrent stdout/stderr capture, a 30-second default timeout, cancellation propagation, and 1 MiB stdout/stderr limits. `FilesystemAuditScanner` uses the same runner with a 60-second timeout for broader `find` scans. Some commands may expose less detail without elevated privileges, especially process names, firewall rules, `sshd -T` host key access, and `stat` on files owned by other users.

## Rule Coverage

### Firewall

- Firewall should be active.
- INPUT default policy should not be broadly permissive.
- SSH should not be exposed to all sources without restriction.
- Established/related connection state tracking should be present.
- ICMP should not be blanket-accepted without review.

### Ports

- SSH listening on port 22 is reported as informational.
- Services listening on all interfaces are reviewed.
- Common database ports exposed on all interfaces are Critical.
- Unknown high-port listeners without process names are reported for review.

### Services

- Telnet should not be running.
- FTP should not be running when SFTP/SSH alternatives exist.
- SSH presence is checked for expected remote administration.
- Legacy r-services are flagged.
- Common unnecessary services such as CUPS, Avahi, Bluetooth, NFS, RPC, SMB, and NetBIOS are reviewed.

### Network

- A default route should exist.
- Suspicious established outbound connections to high-risk ports are flagged.
- At least one interface should be up.
- Services intended for loopback should not also listen on all interfaces.

### SSH

- Direct root login should be disabled or limited to key-based auth (`PermitRootLogin`).
- Password authentication should be disabled in favor of key-based auth (`PasswordAuthentication`).
- Maximum authentication attempts per connection should be low (`MaxAuthTries`).
- Legacy SSH Protocol 1 should not be enabled (`Protocol`).
- Empty passwords should not be permitted (`PermitEmptyPasswords`).
- Public-key authentication should be enabled (`PubkeyAuthentication`).
- X11 forwarding should be disabled on servers (`X11Forwarding`).
- UsePAM should be enabled to enforce local PAM policies (`UsePAM`) (`SSH-008`).

### Kernel

- ASLR should be fully enabled (`kernel.randomize_va_space >= 2`) (`KERN-001`).
- IP forwarding should be disabled on non-router hosts (`net.ipv4.ip_forward`, `net.ipv6.conf.all.forwarding`) (`KERN-002`).
- ICMP redirects should be disabled (`net.ipv4.conf.all.accept_redirects`, `net.ipv6.conf.all.accept_redirects`) (`KERN-003`).
- Source routed packets should be rejected (`net.ipv4.conf.all.accept_source_route`) (`KERN-004`).
- Kernel module loading should be restricted (`kernel.modules_disabled != 0`); severity is High on Server, Medium on Workstation (`KERN-005`).
- Secure Boot should be enabled on UEFI systems; BIOS systems return NotApplicable (`KERN-006`).
- Kernel pointer and dmesg exposure should be restricted (`kernel.kptr_restrict >= 1`, `kernel.dmesg_restrict == 1`) (`KERN-007`).

### File Permissions

- `/etc/shadow` should be `640` or `600` and owned by root (`FILE-001`).
- `/etc/passwd` should be `644` and owned by root (`FILE-002`).
- SSH host private keys should be `600` and owned by root (`FILE-003`).
- `/root/.ssh` should be `700` and `/root/.ssh/authorized_keys` should be `600` (`FILE-004`).
- Cron directories should not be world-writable (`FILE-005`).
- `/etc/crontab` should be `644` or `600` and owned by root (`FILE-006`).
- User SSH directories (`/home/*/.ssh`) should be `700` and user `authorized_keys` files should be `600` (`FILE-007`).

### Filesystem Audit

- World-writable files outside expected temporary paths (`/tmp`, `/var/tmp`, `/dev/shm`, `/var/cache`, `/var/spool`) are flagged (`FSYS-001`).
- SUID/SGID binaries that do not match the known-good full-path whitelist are flagged (`FSYS-002`).
- Files with no valid owner or group are flagged (`FSYS-003`).
- World-writable directories without the sticky bit are flagged (`FSYS-004`).
- `/tmp` should be a separate mount with `noexec`, `nosuid`, and `nodev` options (`FSYS-005`).

### User Accounts

- Only `root` should have UID 0; additional UID-0 accounts are flagged (`USER-001`).
- Empty or unset password hashes are flagged; locked interactive accounts are flagged at lower severity (`USER-002`).
- Password aging should enforce rotation via `PASS_MAX_DAYS <= 90`, `PASS_MIN_DAYS >= 1`, and `PASS_WARN_AGE >= 7` in `/etc/login.defs`, plus per-user shadow `max_days` checks (`USER-003`).
- PAM password-stack should include a complexity module (`pam_pwquality.so`, `pam_cracklib.so`, or `pam_passwdqc.so`) (`USER-004`).
- Inactive or locked interactive accounts (UID >= 1000) with expired account expiry dates are flagged (`USER-005`).
- Each UID should be unique (`USER-006`).
- Regular interactive accounts (UID >= 1000) should have an existing home directory (`USER-007`).
- PAM faillock must be configured in every auth stack (`preauth` + `authfail`) with a readable `faillock.conf` (`USER-008`).
- PAM password quality must enforce `minlen >= 14`, `minclass >= 3`, and credit requirements (`dcredit`, `ucredit`, `lcredit`, `ocredit`) (`USER-009`).
- PAM auth stack must place `required`/`requisite`/`binding` or bracketed controls before any `sufficient` module in every file (`USER-010`).

### Logging

- At least one system logging service (rsyslog or journald) should be active (`LOG-001`).
- auditd should be installed and active (`LOG-002`).
- auditd should have active rules monitoring key security events (`LOG-003`). Returns `NotApplicable` when auditd rules could not be read (permission denied).
- Log rotation should be configured via logrotate (`LOG-004`).
- Central log forwarding should be configured (rsyslog remote or journald `ForwardToSyslog`); exempt on Workstation, DevMachine, LabBox, and Router (`LOG-005`).
- auditd should monitor privilege escalation syscalls (`setuid`, `setgid`, etc.) (`LOG-006`). Returns `NotApplicable` when auditd rules could not be read.
- Central forwarding should use TCP (`@@` target) rather than UDP (`@`) for reliability (`LOG-007`).

### Cron Jobs

- Cron entries should not contain suspicious commands such as reverse shells, network downloaders (`wget`, `curl`, `nc`), temporary paths (`/tmp/`, `/var/tmp/`, `/dev/shm/`), or encoded payloads (`python -c`, `perl -e`, etc.). Pattern matching uses word-boundary awareness to reduce false positives (`CRON-001`).
- Script files in `cron.daily`, `cron.hourly`, `cron.weekly`, and `cron.monthly` should not be world-writable. Setuid/setgid bits on cron scripts are escalated to `Critical` severity (`CRON-002`).
- System crontab entries running as `root` should not reference non-root user directories (e.g., paths under `/home/` or `~username` expansions) (`CRON-003`).
- All cron rules return `NotApplicable` when no cron data is available (requires root or cron files not present).

### Package Vulnerability

- Pending security updates from security repositories should be applied promptly. Severity escalates to `Critical` when 5 or more security updates are pending (`PKG-VULN-001`).
- Automatic security updates via `unattended-upgrades` should be configured (`PKG-VULN-002`).
- Known CVEs affecting installed packages should be tracked and patched. Returns `NotApplicable` when CVE enrichment data (debsecan) is unavailable, preventing false confidence on systems without CVE data (`PKG-VULN-003`).
- All package vulnerability rules return `NotApplicable` when package data is unreadable (dpkg-query failed or permission denied).

### Container

- Privileged containers should not be running (`CTR-001`).
- Container images should not use the `latest` tag or no explicit tag (`CTR-002`).
- The Docker socket should not be exposed on the host or mounted into containers (`CTR-003`).
- Containerd should use explicit namespaces rather than only the default (`CTR-004`).
- Container images should not use known risky base-image hints, such as end-of-life distro bases detected from local image references or base-image labels (`CTR-005`).
- All container rules return `Pass` when no container runtime is available.

### Kubernetes

- Pods should not run privileged containers (`K8S-001`).
- Pods should not use `hostNetwork`, `hostPID`, or `hostIPC` (`K8S-002`).
- Containers should run as non-root (`K8S-003`).
- Containers should have hardened security contexts (`allowPrivilegeEscalation: false`, `readOnlyRootFilesystem`, drop ALL capabilities, and a confined seccomp profile) (`K8S-004`).
- Pod-level `securityContext` is inherited by containers; container-level settings override pod-level.
- All Kubernetes rules return `Pass` when no kubeconfig is present or `kubectl` is unavailable.

### YARA

- Files matching bundled or custom YARA rules on SUID/SGID binaries, running process executables, or cron scripts are flagged (`YARA-001`).
- The bundled rule set focuses on Linux ELF packers, SUID backdoor signatures, and common malware families.
- Custom rules can be dropped into `~/.config/VulcansTrace/yara/*.yar` and are automatically compiled and scanned alongside bundled rules.
- The scanner reports `Unavailable` when `libyara` is not installed, and `PermissionLimited` when some targets cannot be read.

### Process Runtime

- **PROC-001** (Critical) — Processes with RWX (`rwxp`) memory mappings in `/proc/<pid>/maps` indicate potential process injection or shellcode (MITRE T1055, T1620).
- **PROC-002** (High) — Processes with `LD_PRELOAD` or `LD_AUDIT` environment variables indicate dynamic linker hijacking (MITRE T1574.006).
- **PROC-003** (High) — Processes executing from deleted binaries (`(deleted)` suffix on `/proc/<pid>/exe`) or temporary paths (`/tmp`, `/var/tmp`, `/dev/shm`) indicate anti-forensics or dropped payloads (MITRE T1036, T1105).
- **PROC-004** (Medium) — Orphaned processes (PPid=1) with anomalous names (≥10 chars, alphanumeric, ≥3 digits) indicate daemonized malware or persistence (MITRE T1036).
- **PROC-005** (High) — Suspicious parent-child relationships: web servers (`apache2`, `nginx`, `httpd*`) spawning interpreters, SSH spawning non-shell interpreters, databases spawning shells, or cron spawning network tools (MITRE T1059).
- **PROC-006** (Critical) — Interpreter processes (python, perl, ruby, php, including versioned binaries) with RWX mappings indicate in-memory payload execution or native-extension abuse (MITRE T1055, T1620, T1059).
- All process runtime rules return `NotApplicable` when no `/proc` data is available.
- Evidence-specific process runtime rules return `NotApplicable` when their required `/proc` evidence is entirely unreadable, and include unreadable-count metadata when only part of the process set was visible.
- Rules intentionally carry **no CIS mappings** — they are DFIR indicators rather than configuration compliance checks.

## How The Pipeline Works

1. `DialogueManager` resolves the raw query in conversation context. It first runs `QueryParser` to produce an `AgentQuery` with intent, confidence, alternatives, and target reference, then `EntityExtractor` populates a `QueryEntityFrame` with rule IDs, categories, session IDs, severity filters, time windows, remediation verbs, and ordinals. `AnaphoraResolver` resolves pronouns and ordinals, and finally `IntentInferenceEngine` applies topic-aware deterministic inference. Ambiguous audit-area prompts ask for clarification instead of running a guessed check.
2. `SecurityAgent` acts as the orchestration entry point and delegates scanner execution to `ScannerCoordinator`.
3. `ScanDataBuilder` collects scanner output and data-source capability status into a thread-safe snapshot.
4. `RuleEvaluationService` resolves built-in role defaults and user overrides from `~/.config/VulcansTrace/policy.json`, filters rules by intent, invokes contextual rules when they opt into `IContextualRule`, converts crashes into explicit rule results, and applies disabled, auto-pass, and severity override policy.
5. `FindingAssemblyService` converts failed rule results into `Finding` records with stable fingerprints derived from rule ID, category, source host, and target. Severity, timestamps, and description text are excluded so the same underlying issue can be tracked when its wording or severity changes.
6. `ExplanationProvider` fills markdown templates for each finding and parses them into structured explanation sections.
7. Suppressions expired longer than the 30-day review retention window are pruned, active fingerprint-scoped suppressions are applied first, legacy rule-ID/target suppressions remain supported, and rule pass/fail/suppressed counts are added to `AgentResult`.
8. `AgentResultComposer` builds user-facing audit summaries and deterministic data-source capability reports.
9. `AgentLogAnalysisService` optionally analyzes pasted firewall logs through `SentryAnalyzer` and adds log-derived findings when raw log text is available.
10. `AgentResultFinalizer` attaches `ComplianceScorecardBuilder` and `RiskScorecardBuilder` output, builds the final `AgentResult`, and updates `AgentAuditState` so follow-up questions like `explain FW-001` can resolve without relying on text matching.
11. `PostureCorrelator` scans failed rule results for known multi-rule posture correlations (e.g., `FW-002+SSH-002`) and adds deduplicated `PostureCorrelation` records to `AgentResult`.
12. `RuleMemoryRecorder` updates the per-rule memory history with severity snapshots and trend status from the current audit.
13. `NarrativeComposer` builds the multi-paragraph `AgentResult.Narrative` from findings, posture correlations, rule-memory history, and data-source capability data, ensuring every non-generic paragraph cites source IDs.
14. `AgentSuggestionProvider` generates deterministic follow-up suggestions from the final `AgentResult` and `EntityFrame`, including correlated-pair fixes, stale/worsening prioritization, and verification follow-ups.
15. `AgentFollowUpService`, `FindingExplanationService`, and `SingleRuleExplanationService` answer deterministic follow-up questions and explanation requests without making `SecurityAgent` own those workflows directly.
16. `BaselineDriftService` saves baseline snapshots from audit results and compares live state against the active intent-scoped baseline through `AuditDiffCalculator`. Each baseline stores lightweight `AuditSnapshotFinding` records for diff calculations and preserves the original `Finding` objects for lossless display.
17. `ComplianceScorecardBuilder` produces a formal CIS Compliance Scorecard from rule results: per-family pass/fail/warn scores, overall percentage, and trend over time. The scorecard is surfaced in the Avalonia UI Compliance tab and exported as `compliance-scorecard.html` and `compliance-scorecard.md` in evidence bundles.
18. `RiskScorecardBuilder` produces an aggregate Risk Scorecard from agent findings: numeric score (0-100), letter grade (A-F), summary status, and per-category breakdown ordered by total deduction. It weights each finding by the average `ControlWeight` of its CIS mappings (default 1.0, with guards against zero, negative, NaN, Infinity, and excessive weights). The scorecard is surfaced in the Avalonia UI Risk Score tab, available via agent chat (`what's my risk grade?`), and exported as `risk-scorecard.html` and `risk-scorecard.md` in evidence bundles.
19. `AgentReportGenerator` can merge agent findings and log findings into an `AnalysisResult`; exported CSV, JSON, Markdown, HTML, and STIX evidence preserves agent rule IDs, fingerprints, data-source capability reports, active suppression notes, and risk scorecard data when present.

## Rule Tuning

The agent supports local role-aware policy for `Workstation`, `Server`, `LabBox`, `Router`, and `DevMachine` profiles. Built-in defaults tune selected rules, and user JSON policies take precedence while inheriting built-in parameters that are not overridden.

The policy file lives at `~/.config/VulcansTrace/policy.json`. It can disable a rule, auto-pass a rule, override severity, or provide rule-specific parameters. Current contextual rules include `PORT-001`, `PORT-002`, `SRV-005`, `SSH-007`, `KERN-005`, and `LOG-005`.

The Avalonia composition currently runs the agent as `Workstation`; other roles are available through the agent API and policy provider wiring until a role selector is added.

## Explanation Behavior

The agent supports three explanation paths:

- **Selected finding:** if the user selects a finding in the UI and asks `explain this finding`, `AgentViewModel` calls `ExplainFindingAsync` directly without re-scanning.
- **Previous agent finding:** after an audit, references such as `explain FW-001`, `explain firewall`, or `explain SSH` are resolved against cached agent findings.
- **Known rule ID with no cached finding:** if a rule ID is recognized but no previous finding is available, the agent runs that single rule and explains the result if it fails.

When no selected finding or target reference is available, the agent returns guidance instead of running an unrelated full audit.

Explanations are rendered as structured sections: what was found, why it matters, how to verify, preconditions, backup commands, suggested next action, rollback commands, confidence, and caveats. Each explanation includes MITRE ATT&CK technique context when the triggering rule has technique mappings, helping analysts understand the adversary behavior the finding addresses. The UI extracts copyable commands only from the verification section and labels them with a heuristic safety classification plus structural badges for sudo usage, command chains, pipes, redirects, and download-and-execute patterns. Suggested action commands are kept in the explanation/remediation preview path, safety-labeled in exported remediation plans with the same structural warnings, and never applied automatically.

**Interactive Remediation Preview** — When a user asks `fix FW-001` after an audit, the agent builds a single-section `RemediationPlan` for that finding, runs `RemediationPlanValidator` to ensure risky or unclassified commands have explicit rollback guidance, and returns the plan as an interactive remediation card only when validation succeeds. The card opens with a compact **Impact Preview** panel summarizing the expected impact, rollback path, verification command, risk before/after, command count, rollback availability, restart impact, and lockout risk before the detailed command lists. Below that, it surfaces preconditions as a checklist, backup commands, apply commands, rollback commands, and verification commands — each with the same safety and structural badges used for verification commands. Rollback paths rendered in the preview are displayed in monospace font when they are actual commands, or in the default prose font when they are natural-language hints. If validation fails because rollback guidance is missing, the plan is blocked and the UI does not expose copyable apply/backup commands.

**Guided Remediation Sessions** — When a user asks `remediate FW-001`, `guided fix FW-001`, or `start remediation FW-001`, the agent creates a persisted `RemediationSession` with a before snapshot, per-rule step state, and the generated remediation plan. Safe sessions show the same manual command workflow as the preview path — including the compact impact preview panel with full simulation data — plus a **Verify Remediation** action. Blocked sessions are marked `Blocked`, show the safety reasons, do not expose the command card, and cannot be verified as completed remediation. Verification (`verify remediation abc12345` or the session card button) re-runs the original audit intent, captures an after snapshot, and reports fixed, unchanged, new, and worsened findings. If verification cannot run or crashes after starting, the session timeline records `VerificationBlocked` or `VerificationFailed` so the audit trail does not end at `VerificationStarted`. **Export Session** writes a markdown session report with step state, blocked reasons, before snapshot, remediation plan, and verification diff when present; the `Exported` event is persisted only after the file write succeeds.

## UI Integration

The Avalonia application exposes the agent in a collapsible Security Agent panel. The panel supports:

- Chat-style natural-language questions.
- Quick-action buttons for full audit, firewall, ports, services, network, containers, Kubernetes, selected-finding explanation, and audit export.
- Baseline quick-action buttons for **Set Baseline**, **Check Drift**, and **Show Baseline**.
- In-flight query cancellation.
- Data-source capability messages showing whether scanner inputs such as iptables, nftables, ss, netstat, ip, and systemctl were available, unavailable, permission-limited, or not checked.
- Agent findings grouped by category with compact severity summaries. Similar repeated findings are also collapsed by the shared noise-budget pipeline, preserving `GroupedCount`, representative targets, and risk drivers in chat, the findings grid, history, drift, and exports.
- Chat filters for severity and category that hide/show finding groups without changing the underlying audit result.
- A Coverage tab after agent audits with totals and category breakdowns for passed, active failed, suppressed, and crashed rule checks.
- A Compliance tab showing the CIS Compliance Scorecard with an overall score badge (Pass ≥90%, Warn ≥80%, Fail <80%), per-family DataGrid with score and status, and a mini bar-chart trend visualization of previous audits.
- A Risk Score tab showing the aggregate Risk Scorecard with a color-coded grade badge (A–F), numeric score, summary status, and a per-category breakdown ordered by total deduction.
- Two-way selection tracking from the findings grid for selected-finding explanations; the Explain Selected action is only enabled when a finding is selected.
- Agent audit results are loaded into the shared findings grid so they can be selected, explained, exported, or suppressed. This includes quick-action audits and typed audit intents such as SSH, file permission, kernel hardening, cron job, package vulnerability, container, and Kubernetes checks.
- An elevated-privilege warning banner when scanner output indicates permission-limited visibility.
- Role-aware rule tuning through local policy, currently wired as `Workstation` in the desktop UI.
- **Follow-up suggestion chips** — every agent message with suggestions shows a row of clickable chips (`What should I fix first?`, `Fix it`, `Check drift`, etc.). Clicking a chip runs the underlying query.
- **Narrative rendering** — the composed `AgentResult.Narrative` is rendered in the chat panel with `**bold**` and `*italic*` styling via `MarkdownInlinesConverter`; intraword underscores are preserved so snake_case rule IDs stay readable.
- **Cross-session memory** — the agent restores the last conversation context (topic, focused finding, recent turns, rule history, and last result) when the Avalonia app restarts, using the lightweight `agent-memory.json` snapshot and the existing audit-history store.
- Audit history persisted to the user config directory when available, capped at 50 lightweight snapshots by default, with compare-last-two, selectable before/after comparison, deterministic narrative diff summaries, and exported-state tracking after successful evidence export. If persistence fails, the UI reports that history is session-only.
- Configuration baselines persisted to the user config directory (`~/.config/VulcansTrace/baselines.json`) when available, with in-memory fallback. Baselines are intent-scoped; each intent has one active baseline at a time. Drift detection re-runs the last completed audit intent and compares against the active baseline, surfacing new and worsened findings.
- Accept Risk suppressions by finding fingerprint when available, with legacy rule-ID/target matching for older entries. Suppressions can last 7 days, 30 days, 90 days, or permanently. Expired suppressions stop applying immediately, remain in the review queue for 30 days, and are pruned after that retention window. Suppressions are persisted to the user config directory when available; if persistence fails, the UI reports that suppressions are session-only.
- A Suppressions tab with friendly filter labels, review counts, status badges, and row actions to renew, convert duration, edit reason, or remove suppressions.
- Export Audit support that reuses the shared evidence export flow for the latest agent audit and includes active suppression notes when present.
- Export Remediation support that writes a review-only markdown plan with an impact preview block, preconditions, backup/apply/rollback command sections, safety notes, rollback hints, and verification commands. Plans with risky or unclassified apply/backup commands are blocked from standalone export and omitted from evidence bundles unless the template includes explicit rollback guidance.
- **Interactive Remediation Preview** (`fix FW-001`) surfaces a single-section remediation card in the chat with preconditions, backup commands, apply commands, rollback commands, and verification commands — each labeled with safety and structural badges. The plan is validated before display; missing rollback guidance for risky commands blocks the card and surfaces the error in chat without exposing copyable commands.
- **Guided Remediation Sessions** (`remediate FW-001`) persist a manual remediation workflow with a before snapshot, step state, session ID, verification action, immutable event timeline, and markdown session export. Blocked sessions remain visible for auditability but do not expose the command card or allow verification as completed remediation. Verification failures and successful report exports are recorded as terminal timeline events.
- **Remediation Session Notes** — During an existing session, you can append free-text notes via chat: `add note to session abc12345 reviewed firewall policy with security team` or `note for step FW-001 in session abc12345 applied iptables rule, verified with ss -tulnp`. Notes support lightweight evidence syntax (`[reference]` and `` `reference` ``) that is extracted into traceable `EvidenceLinks` and stripped from the displayed text. Notes are rendered in exported session markdown under a `## Notes` section and recorded as `SessionNoteAdded`/`StepNoteAdded` timeline events.
- **Remediation Session History Browser** — A **Remediation Sessions** expander in the Avalonia UI lists all persisted sessions with ID, status, rule ID, and creation time. Select a session and click **Resume** to reload it into the chat panel (records a `SessionResumed` timeline event), or click **Delete** to remove it from the store. Chat commands `list my sessions`, `show sessions`, and `resume session <id>` provide the same functionality through natural language.
- **Batch Auto-Fix** (`--auto-fix` on the CLI) extends interactive remediation to headless batch mode. After an audit, the CLI can build a `RemediationPlan` for all findings, filter commands through a configurable `AutoFixPolicy`, execute backup/apply/verify phases sequentially, and automatically roll back a section if any apply command fails. `--dry-run` previews the plan without executing anything. The default policy permits `ReadOnly` verification and `ConfigChange` commands; `--allow-restart` and `--allow-packages` expand the policy; destructive and unclassified commands are never auto-executed.
- Automatic sharing of the main log input with the agent so pasted firewall logs can be included in agent analysis.

## Privacy And Safety

- The agent is local-only.
- It does not send telemetry or analysis data to third-party services. Kubernetes audits run `kubectl` against the user's configured cluster context when kubeconfig exists.
- It reads host state through local Linux commands.
- It does not modify firewall rules, services, network interfaces, routes, or files.
- It reports warnings when data cannot be collected.
- It reports data-source capability status so exported evidence shows which local commands informed the audit.

## CIS Benchmark Mapping

Every agent rule maps to **two compliance layers**:

1. **CIS Controls v8** (organizational) — e.g., `CIS 4.5`, `CIS 5.4`, `CIS 6.3`
2. **CIS Ubuntu 24.04 LTS Benchmark** (technical) — e.g., `5.2.7 Ensure SSH root login is disabled`

This dual-layer mapping gives auditors both the high-level organizational control and the exact Linux benchmark section the rule validates. The mapping flows through every execution path: full audits, single-rule explanations, crashes, policy-disabled results, and all evidence exports.

| Rule | CIS Control | Ubuntu Benchmark |
|------|-------------|------------------|
| KERN-001 | CIS 1.5 — Establish and Maintain a Secure Configuration Process | 1.5.2 — Ensure address space layout randomization is enabled |
| KERN-002 | CIS 3.1 — Network Parameters (Host Only) | 3.1.1 — Ensure IP forwarding is disabled |
| KERN-003 | CIS 3.1 — Network Parameters (Host Only) | 3.1.2 — Ensure ICMP redirects are not accepted |
| KERN-004 | CIS 3.1 — Network Parameters (Host Only) | 3.1.3 — Ensure source routed packets are not accepted |
| KERN-005 | CIS 1.4 — Secure Boot Settings | 1.4.1 — Ensure loading and unloading of kernel modules is restricted |
| KERN-006 | CIS 1.4 — Secure Boot Settings | 1.4.2 — Ensure Secure Boot is enabled |
| KERN-007 | CIS 1.5 — Establish and Maintain a Secure Configuration Process | 1.5.3 — Ensure kernel pointer restriction is enabled |
| SSH-001 | CIS 5.4 — Restrict Administrator Privileges | 5.2.7 — Ensure SSH root login is disabled |
| SSH-002 | CIS 6.3 — Require MFA for Externally-Exposed Applications | 5.2.16 — Ensure SSH PasswordAuthentication is disabled |
| SSH-003 | CIS 6.3 — Require MFA for Externally-Exposed Applications | 5.2.14 — Ensure SSH MaxAuthTries is configured |
| SSH-004 | CIS 4.8 — Uninstall or Disable Unnecessary Services | 5.2.15 — Ensure SSH Protocol is set to 2 |
| SSH-005 | CIS 5.2 — Use Unique Passwords | 5.2.9 — Ensure SSH PermitEmptyPasswords is disabled |
| SSH-006 | CIS 6.3 — Require MFA for Externally-Exposed Applications | 5.2.17 — Ensure SSH PubkeyAuthentication is enabled |
| SSH-007 | CIS 4.8 — Uninstall or Disable Unnecessary Services | 5.2.12 — Ensure SSH X11 forwarding is disabled |
| SSH-008 | CIS 5.2 — Use Unique Passwords | 5.2.20 — Ensure SSH PAM is enabled |
| FILE-001 | CIS 6.1 — Configure System File Permissions | 6.1.1 — Ensure permissions on /etc/shadow are configured |
| FILE-002 | CIS 6.1 — Configure System File Permissions | 6.1.2 — Ensure permissions on /etc/passwd are configured |
| FILE-003 | CIS 5.2 — Use Unique Passwords | 5.2.2 — Ensure permissions on SSH private host key files are configured |
| FILE-004 | CIS 5.2 — Use Unique Passwords | 5.2.4 — Ensure permissions on SSH public host key files are configured |
| FILE-005 | CIS 6.1 — Configure System File Permissions | 6.1.3 — Ensure permissions on /etc/cron.* are configured |
| FILE-006 | CIS 6.1 — Configure System File Permissions | 6.1.4 — Ensure permissions on /etc/crontab are configured |
| FILE-007 | CIS 5.2 — Use Unique Passwords | 5.2.4 — Ensure permissions on SSH public host key files are configured |
| FSYS-001 | CIS 6.1.9 — Ensure no world writable files exist | 6.1.9 — Ensure no world writable files exist |
| FSYS-002 | CIS 6.1.12 — Ensure SUID and SGID files are reviewed | 6.1.12 — Ensure SUID and SGID files are reviewed |
| FSYS-003 | CIS 6.1.11 — Ensure no unowned files or directories exist | 6.1.11 — Ensure no unowned files or directories exist |
| FSYS-004 | CIS 6.1.10 — Ensure sticky bit is set on all world-writable directories | 6.1.10 — Ensure sticky bit is set on all world-writable directories |
| FSYS-005 | CIS 1.1.2 — Configure /tmp | 1.1.2.2-4 — Ensure nodev, nosuid, noexec options set on /tmp partition |
| USER-001 | CIS 6.2 — Configure System Account Security | 6.2.1 — Ensure accounts in /etc/passwd use assigned UIDs |
| USER-002 | CIS 5.4 — Configure Password Policies | 5.4.1 — Ensure password creation requirements are configured |
| USER-003 | CIS 5.4 — Configure Password Policies | 5.4.1 — Ensure password creation requirements are configured |
| USER-004 | CIS 5.4 — Configure Password Policies | 5.4.1 — Ensure password creation requirements are configured |
| USER-005 | CIS 6.2 — Configure System Account Security | 6.2.5 — Ensure inactive accounts are locked or removed |
| USER-006 | CIS 6.2 — Configure System Account Security | 6.2.1 — Ensure accounts in /etc/passwd use assigned UIDs |
| USER-007 | CIS 6.2 — Configure System Account Security | 6.2.6 — Ensure all users' home directories exist |
| USER-008 | CIS 5.3 — Configure PAM | 5.3.2 — Ensure lockout for failed password attempts is configured |
| USER-009 | CIS 5.4 — Configure Password Policies | 5.4.1 — Ensure password creation requirements are configured |
| USER-010 | CIS 5.3 — Configure PAM | 5.3.1 — Ensure password hashing algorithm is configured |
| FW-001 | CIS 4.5 — Implement and Manage a Firewall on Servers | 3.5.1.3 / 3.5.2.3 — Ensure default deny firewall policy |
| FW-002 | CIS 4.5 — Implement and Manage a Firewall on Servers | 3.5.1.6 / 3.5.2.6 — Ensure firewall rules exist for all open ports |
| FW-003 | CIS 4.5 — Implement and Manage a Firewall on Servers | 3.5.1.2 / 3.5.2.2 — Ensure iptables/nftables service is enabled |
| FW-004 | CIS 4.5 — Implement and Manage a Firewall on Servers | 3.5.1.1 / 3.5.2.1 — Ensure iptables/nftables is installed |
| FW-005 | CIS 4.5 — Implement and Manage a Firewall on Servers | 3.5.1.5 / 3.5.2.5 — Ensure outbound and established connections are configured |
| PORT-002 | CIS 4.1 — Establish and Maintain a Secure Configuration Process | 3.5.1.6 / 3.5.2.6 — Ensure firewall rules exist for all open ports |
| PORT-003 | CIS 4.1 — Establish and Maintain a Secure Configuration Process | 3.5.1.6 / 3.5.2.6 — Ensure firewall rules exist for all open ports |
| SRV-001 | CIS 4.8 — Uninstall or Disable Unnecessary Services | 2.2.17 — Ensure telnet server is not installed |
| SRV-002 | CIS 4.8 — Uninstall or Disable Unnecessary Services | 2.2.12 — Ensure FTP server is not installed |
| SRV-004 | CIS 4.8 — Uninstall or Disable Unnecessary Services | 2.2.16 — Ensure rsh server is not installed |
| SRV-005 | CIS 4.8 — Uninstall or Disable Unnecessary Services | 2.2.x — Ensure unnecessary services are removed or disabled |
| LOG-001 | CIS 8.1 — Collect and Retain Audit Logs | 4.2.1 — Ensure rsyslog or journald is installed and active |
| LOG-002 | CIS 8.2 — Collect Audit Logs | 4.1.1 — Ensure auditd is installed and active |
| LOG-003 | CIS 8.2 — Collect Audit Logs | 4.1.x — Ensure audit rules are configured |
| LOG-004 | CIS 8.3 — Collect Service Provider Logs | 4.3.x — Ensure logrotate is configured |
| LOG-005 | CIS 8.4 — Collect Audit Log Details | 4.2.2.x — Ensure rsyslog is configured to send logs to a remote log host |
| LOG-006 | CIS 8.2 — Collect Audit Logs | 4.1.x — Ensure audit rules monitor privilege escalation |
| LOG-007 | CIS 8.4 — Collect Audit Log Details | 4.2.2.x — Ensure reliable log forwarding transport |
| CRON-001 | CIS 6.1 — Configure System File Permissions | 6.1.3 — Ensure permissions on /etc/cron.* are configured |
| CRON-002 | CIS 6.1 — Configure System File Permissions | 6.1.3 — Ensure permissions on /etc/cron.* are configured |
| CRON-003 | CIS 6.2 — Configure System Account Security | 6.2.1 — Ensure accounts in /etc/passwd use assigned UIDs |
| PKG-VULN-001 | CIS 1.9 — Ensure updates, patches, and additional security software are installed | 1.9 — Ensure updates, patches, and additional security software are installed |
| PKG-VULN-002 | CIS 1.9 — Ensure updates, patches, and additional security software are installed | 1.9 — Ensure updates, patches, and additional security software are installed |
| CTR-001 | CIS 5.4 — Ensure Privileged Containers Are Not Used | CIS Docker Benchmark 5.4 — Ensure that privileged containers are not used |
| CTR-002 | CIS 4.1 — Ensure Image Pinning Is Used | CIS Docker Benchmark 4.1 — Ensure that a fixed tag or digest is used for base images |
| CTR-003 | CIS 5.25 — Ensure Docker Socket Is Not Mounted Inside Containers | CIS Docker Benchmark 5.25 — Ensure that the Docker socket is not exposed or mounted inside any containers |
| CTR-004 | CIS 1.1 — Use Explicit Namespaces for Workload Isolation | CIS Containerd Benchmark 1.1 — Use explicit namespaces for workload isolation |
| CTR-005 | CIS 4.1 — Ensure Image Pinning Is Used | CIS Docker Benchmark 4.1 — Ensure that a fixed and maintained image base is used |
| K8S-001 | CIS 5.2.1 — Minimize Admission of Privileged Containers | CIS Kubernetes Benchmark 5.2.1 — Minimize the admission of privileged containers |
| K8S-002 | CIS 5.2.4 — Minimize Admission of HostNetwork and HostPID | CIS Kubernetes Benchmark 5.2.4 — Minimize the admission of containers wishing to share the host network namespace |
| K8S-003 | CIS 5.2.6 — Minimize Admission of Root Containers | CIS Kubernetes Benchmark 5.2.6 — Minimize the admission of root containers |
| K8S-004 | CIS 5.2.7 — Enforce Security Context Constraints | CIS Kubernetes Benchmark 5.2.7 — Enforce hardened container security contexts |
| PROC-001 | *(no CIS mapping — DFIR indicator)* | *(no direct benchmark mapping)* |
| PROC-002 | *(no CIS mapping — DFIR indicator)* | *(no direct benchmark mapping)* |
| PROC-003 | *(no CIS mapping — DFIR indicator)* | *(no direct benchmark mapping)* |
| PROC-004 | *(no CIS mapping — DFIR indicator)* | *(no direct benchmark mapping)* |
| PROC-005 | *(no CIS mapping — DFIR indicator)* | *(no direct benchmark mapping)* |
| PROC-006 | *(no CIS mapping — DFIR indicator)* | *(no direct benchmark mapping)* |

The remaining rules (NET-001 through NET-004, PORT-001, PORT-004, SRV-003, PKG-VULN-003) map to CIS Controls v8 where no direct Ubuntu benchmark section exists. KERN-006 returns `NotApplicable` on BIOS systems where Secure Boot is unavailable. PKG-VULN-003 returns `NotApplicable` when CVE enrichment data (debsecan) is unavailable. Process runtime rules (PROC-001..006) are DFIR indicators and intentionally do not map to CIS Benchmark controls.

Mappings are defined on `IRule.CisMappings`, flow through `RuleResult.CisMappings`, and are attached to `Finding.CisMappings` in both the full audit and single-rule explain paths. Evidence exports preserve them in CSV, HTML, Markdown, JSON, and STIX formats.

## Current Limitations

- It is a deterministic, conversation-aware rule-based assistant, not an LLM-backed conversational system. Conversation context is persisted across application restarts via the lightweight `IAgentMemoryStore`; it is never sent to an external service.
- `SecurityAgent.AskAsync` is currently single-threaded. `DialogueManager.Resolve` snapshots `EntityFrame` under the context lock to make the read contract explicit, but concurrent callers should serialize at the UI/CLI layer until a broader concurrency review is done.
- Scanner parsers are pragmatic and command-output based, so unusual distro output may need parser tests and adjustments.
- Capability status reports command availability and permission visibility, not semantic completeness of every data source.
- Some findings are posture checks rather than proof of compromise.
- Process names and firewall details may require elevated privileges depending on the host.
- Deterministic follow-up questions (changes, critical explanations, category filtering, remediation prioritization, interactive remediation, and suppressed listing) operate on the last audit result without re-running scans. They require a prior audit context; when context is missing they return guidance or fall back to a targeted audit for category-filter queries.
- New suppressions are fingerprint-scoped when the selected finding has a fingerprint. Older suppressions without fingerprints still match by rule ID and target, so intentional target text changes can require accepting the risk again.
- Command safety labels use conservative keyword heuristics. Unknown means "not classified," not "safe."
- The desktop UI includes a machine-role dropdown for hot-swapping roles without code changes.
- Process runtime scanning reads live `/proc` state; race conditions, PID reuse, and namespace boundaries can cause transient inconsistency. Read caps (64 KB cmdline, 256 KB environ, 512 KB maps) are surfaced as truncation metadata when exceeded. Thread-level injection into individual threads of a multi-threaded process would not surface distinct maps entries.

## Roadmap

- Expand conversation-aware inference to cover more remediation note and session-management shortcuts.
- Add a policy editing surface in the Avalonia UI.
- Expand scanner fixtures across more distributions and command variants.
- Add reminder surfaces for upcoming suppression review dates.
- Add a "Fix Selected" quick-action button that invokes the same interactive remediation path as `fix <rule-id>`.

## Implementation Evidence

- [SecurityAgent.cs](../VulcansTrace.Linux.Agent/SecurityAgent.cs)
- [QueryParser.cs](../VulcansTrace.Linux.Agent/Query/QueryParser.cs)
- [ScanData.cs](../VulcansTrace.Linux.Agent/Scanners/ScanData.cs)
- [ScannerCoordinator.cs](../VulcansTrace.Linux.Agent/Scanners/ScannerCoordinator.cs)
- [FirewallScanner.cs](../VulcansTrace.Linux.Agent/Scanners/FirewallScanner.cs)
- [PortScanner.cs](../VulcansTrace.Linux.Agent/Scanners/PortScanner.cs)
- [ServiceScanner.cs](../VulcansTrace.Linux.Agent/Scanners/ServiceScanner.cs)
- [NetworkScanner.cs](../VulcansTrace.Linux.Agent/Scanners/NetworkScanner.cs)
- [SshConfigScanner.cs](../VulcansTrace.Linux.Agent/Scanners/SshConfigScanner.cs)
- [FilePermissionScanner.cs](../VulcansTrace.Linux.Agent/Scanners/FilePermissionScanner.cs)
- [FilesystemAuditScanner.cs](../VulcansTrace.Linux.Agent/Scanners/FilesystemAuditScanner.cs)
- [KernelHardeningScanner.cs](../VulcansTrace.Linux.Agent/Scanners/KernelHardeningScanner.cs)
- [UserAccountScanner.cs](../VulcansTrace.Linux.Agent/Scanners/UserAccountScanner.cs)
- [LoggingAuditScanner.cs](../VulcansTrace.Linux.Agent/Scanners/LoggingAuditScanner.cs)
- [CronJobScanner.cs](../VulcansTrace.Linux.Agent/Scanners/CronJobScanner.cs)
- [PackageVulnerabilityScanner.cs](../VulcansTrace.Linux.Agent/Scanners/PackageVulnerabilityScanner.cs)
- [YaraScanner.cs](../VulcansTrace.Linux.Agent/Scanners/Yara/YaraScanner.cs)
- [LibyaraEngine.cs](../VulcansTrace.Linux.Agent/Scanners/Yara/LibyaraEngine.cs)
- [bundled.yar](../VulcansTrace.Linux.Agent/Scanners/Yara/Rules/bundled.yar)
- [ProcessRuntimeScanner.cs](../VulcansTrace.Linux.Agent/Scanners/ProcessRuntimeScanner.cs)
- [ProcessRuntimeEntry.cs](../VulcansTrace.Linux.Agent/Scanners/ProcessRuntimeEntry.cs)
- [Security rules](../VulcansTrace.Linux.Agent/Rules/SecurityRules)
- [RuleEvaluationService.cs](../VulcansTrace.Linux.Agent/Rules/RuleEvaluationService.cs)
- [FindingAssemblyService.cs](../VulcansTrace.Linux.Agent/Reports/FindingAssemblyService.cs)
- [AgentResultComposer.cs](../VulcansTrace.Linux.Agent/Reports/AgentResultComposer.cs)
- [AgentLogAnalysisService.cs](../VulcansTrace.Linux.Agent/Reports/AgentLogAnalysisService.cs)
- [AgentResultFinalizer.cs](../VulcansTrace.Linux.Agent/Reports/AgentResultFinalizer.cs)
- [AgentFollowUpService.cs](../VulcansTrace.Linux.Agent/Reports/AgentFollowUpService.cs)
- [GuidedRemediationService.cs](../VulcansTrace.Linux.Agent/Reports/GuidedRemediationService.cs)
- [FindingExplanationService.cs](../VulcansTrace.Linux.Agent/Reports/FindingExplanationService.cs)
- [SingleRuleExplanationService.cs](../VulcansTrace.Linux.Agent/Reports/SingleRuleExplanationService.cs)
- [LoggingAuditRules.cs](../VulcansTrace.Linux.Agent/Rules/SecurityRules/LoggingAuditRules.cs)
- [CronJobRules.cs](../VulcansTrace.Linux.Agent/Rules/SecurityRules/CronJobRules.cs)
- [PackageVulnerabilityRules.cs](../VulcansTrace.Linux.Agent/Rules/SecurityRules/PackageVulnerabilityRules.cs)
- [YaraRules.cs](../VulcansTrace.Linux.Agent/Rules/SecurityRules/YaraRules.cs)
- [AgentViewModel.cs](../VulcansTrace.Linux.Avalonia/ViewModels/AgentViewModel.cs)
- [AgentMessageViewModel.cs](../VulcansTrace.Linux.Avalonia/ViewModels/AgentMessageViewModel.cs)
- [AgentOperationRunner.cs](../VulcansTrace.Linux.Avalonia/ViewModels/AgentOperationRunner.cs)
- [AgentResultPresenter.cs](../VulcansTrace.Linux.Avalonia/ViewModels/AgentResultPresenter.cs)
- [AgentHistoryCoordinator.cs](../VulcansTrace.Linux.Avalonia/ViewModels/AgentHistoryCoordinator.cs)
- [ComplianceScorecardViewModel.cs](../VulcansTrace.Linux.Avalonia/ViewModels/ComplianceScorecardViewModel.cs)
- [RiskScorecardViewModel.cs](../VulcansTrace.Linux.Avalonia/ViewModels/RiskScorecardViewModel.cs)
- [RiskScorecardBuilder.cs](../VulcansTrace.Linux.Agent/Reports/RiskScorecardBuilder.cs)
- [SecurityAgentTests.cs](../VulcansTrace.Linux.Tests/Agent/SecurityAgentTests.cs)
- [ComplianceScorecardBuilderTests.cs](../VulcansTrace.Linux.Tests/Agent/ComplianceScorecardBuilderTests.cs)
- [ScannerParserFixtureTests.cs](../VulcansTrace.Linux.Tests/Agent/ScannerParserFixtureTests.cs)
- [BaselineEntry.cs](../VulcansTrace.Linux.Agent/Baselines/BaselineEntry.cs)
- [IBaselineStore.cs](../VulcansTrace.Linux.Agent/Baselines/IBaselineStore.cs)
- [JsonFileBaselineStore.cs](../VulcansTrace.Linux.Agent/Baselines/JsonFileBaselineStore.cs)
- [BaselineDiffResult.cs](../VulcansTrace.Linux.Agent/Baselines/BaselineDiffResult.cs)
- [RemediationSession.cs](../VulcansTrace.Linux.Agent/Sessions/RemediationSession.cs)
- [ISessionStore.cs](../VulcansTrace.Linux.Agent/Sessions/ISessionStore.cs)
- [JsonFileSessionStore.cs](../VulcansTrace.Linux.Agent/Sessions/JsonFileSessionStore.cs)
- [InMemorySessionStore.cs](../VulcansTrace.Linux.Agent/Sessions/InMemorySessionStore.cs)
- [IAgent.cs](../VulcansTrace.Linux.Agent/IAgent.cs) — public agent interface with `ListRemediationSessionsAsync`, `LoadRemediationSessionAsync`, `DeleteRemediationSessionAsync`, `AddSessionNoteAsync`, and `AddStepNoteAsync`
- [QueryParser.cs](../VulcansTrace.Linux.Agent/Query/QueryParser.cs) — intent parsing including `ListRemediationSessions`, `ResumeRemediation`, `AddSessionNote`, and `AddStepNote`
- [DialogueManager.cs](../VulcansTrace.Linux.Agent/Dialogue/DialogueManager.cs) — orchestrates parsing, anaphora resolution, and intent inference
- [DialogueContext.cs](../VulcansTrace.Linux.Agent/Dialogue/DialogueContext.cs) — conversation state, `SnapshotState`/`RestoreState`, topic/intent mapping
- [EntityFrame.cs](../VulcansTrace.Linux.Agent/Dialogue/EntityFrame.cs) — shallow-copyable entity frame used by resolve/inference
- [EntityExtractor.cs](../VulcansTrace.Linux.Agent/Dialogue/EntityExtractor.cs) — extracts rule IDs, session IDs, ordinals, categories, and anaphora markers
- [AnaphoraResolver.cs](../VulcansTrace.Linux.Agent/Dialogue/AnaphoraResolver.cs) — resolves pronouns and ordinals against a snapshot of the entity frame
- [IntentInferenceEngine.cs](../VulcansTrace.Linux.Agent/Dialogue/IntentInferenceEngine.cs) — deterministic topic-aware intent inference and `BuildTarget`
- [ResponseTemplateProvider.cs](../VulcansTrace.Linux.Agent/Dialogue/ResponseTemplateProvider.cs) — clarification prompts for ambiguous queries
- [AgentQuery.cs](../VulcansTrace.Linux.Agent/Query/AgentQuery.cs) — structured query record with raw query text for inference
- [SuggestedFollowUp.cs](../VulcansTrace.Linux.Agent/Suggestions/SuggestedFollowUp.cs) — follow-up suggestion data
- [AgentSuggestionProvider.cs](../VulcansTrace.Linux.Agent/Suggestions/AgentSuggestionProvider.cs) — deterministic suggestion generation
- [IAgentMemoryStore.cs](../VulcansTrace.Linux.Agent/Memory/IAgentMemoryStore.cs) — cross-session memory store contract
- [AgentMemorySnapshot.cs](../VulcansTrace.Linux.Agent/Memory/AgentMemorySnapshot.cs) — persisted memory snapshot
- [JsonFileAgentMemoryStore.cs](../VulcansTrace.Linux.Agent/Memory/JsonFileAgentMemoryStore.cs) — JSON-backed memory persistence
- [RuleMemoryEntry.cs](../VulcansTrace.Linux.Agent/Memory/RuleMemoryEntry.cs) — per-rule memory record
- [RuleMemoryRecorder.cs](../VulcansTrace.Linux.Agent/Memory/RuleMemoryRecorder.cs) — records severity snapshots and trend status per rule
- [QueryEntityFrame.cs](../VulcansTrace.Linux.Agent/Query/QueryEntityFrame.cs) — structured entity frame for NLU
- [EntityExtractor.cs](../VulcansTrace.Linux.Agent/Query/EntityExtractor.cs) — extracts rule IDs, categories, session IDs, severity filters, time windows, remediation verbs, and ordinals
- [PostureCorrelator.cs](../VulcansTrace.Linux.Engine/PostureCorrelator.cs) — deterministic multi-rule posture correlation
- [NarrativeComposer.cs](../VulcansTrace.Linux.Agent/Dialogue/NarrativeComposer.cs) — composes traceable multi-paragraph agent replies
- [MarkdownInlinesConverter.cs](../VulcansTrace.Linux.Avalonia/Converters/MarkdownInlinesConverter.cs) — renders bold/italic markdown in Avalonia chat
- [Program.cs](../VulcansTrace.Linux.Cli/Program.cs) — CLI entry point including markdown stripping and session management
- [SecurityAgent.cs](../VulcansTrace.Linux.Agent/SecurityAgent.cs) — agent orchestration, including `VerifyFindingAsync`
- [RuleMemoryRecorderTests.cs](../VulcansTrace.Linux.Tests/Agent/Memory/RuleMemoryRecorderTests.cs)
- [NarrativeComposerTests.cs](../VulcansTrace.Linux.Tests/Agent/NarrativeComposerTests.cs)
- [PostureCorrelatorTests.cs](../VulcansTrace.Linux.Tests/Engine/PostureCorrelatorTests.cs)
- [EntityExtractorTests.cs](../VulcansTrace.Linux.Tests/Agent/EntityExtractorTests.cs)
- [AgentSuggestionProviderTests.cs](../VulcansTrace.Linux.Tests/Agent/Suggestions/AgentSuggestionProviderTests.cs)
- [SecurityAgentMemoryIntegrationTests.cs](../VulcansTrace.Linux.Tests/Agent/Memory/SecurityAgentMemoryIntegrationTests.cs)
- [RemediationPlanBuilder.cs](../VulcansTrace.Linux.Agent/Remediation/RemediationPlanBuilder.cs)
- [RemediationExecutor.cs](../VulcansTrace.Linux.Agent/Remediation/RemediationExecutor.cs)
- [AutoFixPolicy.cs](../VulcansTrace.Linux.Agent/Remediation/AutoFixPolicy.cs)
- [ProcessRunner.cs](../VulcansTrace.Linux.Agent/Remediation/ProcessRunner.cs)
- [IProcessRunner.cs](../VulcansTrace.Linux.Agent/Remediation/IProcessRunner.cs)
- [RemediationConsoleFormatter.cs](../VulcansTrace.Linux.Agent/Reports/RemediationConsoleFormatter.cs)
- [RemediationPlanValidator.cs](../VulcansTrace.Linux.Agent/Reports/RemediationPlanValidator.cs)
- [RemediationMarkdownFormatter.cs](../VulcansTrace.Linux.Agent/Reports/RemediationMarkdownFormatter.cs) — renders session notes and evidence links in exported markdown reports
