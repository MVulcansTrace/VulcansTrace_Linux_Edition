# Security Agent

The Security Agent is a local, rule-based Linux security assistant built into VulcansTrace Linux Edition. It answers plain-English security questions, scans live host state, evaluates defensive posture rules, explains findings, and can include pasted firewall logs in the same analysis workflow.

The agent is intentionally deterministic. It does not call an external LLM or send system data to a service. Its value comes from a predictable pipeline: query parsing, local scanners, rule evaluation, explanation templates, and compatibility with the existing VulcansTrace `AnalysisResult` and evidence pipeline.

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
| `Explain FW-001` | `ExplainFinding` | Explains a cached finding by rule ID, or runs that single rule if needed |
| `Explain this finding` | `ExplainFinding` | Explains the currently selected UI finding when one is selected |
| `What changed since the last audit?` | `ShowChanges` | Diff the current audit against the previous history entry |
| `Why is this critical?` | `ExplainCritical` | Explain only Critical/High findings from the last audit |
| `Show only firewall issues` | `FilterCategory` | Filter the last audit's findings by category (falls back to a fresh category audit when no context exists) |
| `What should I fix first?` | `PrioritizeRemediation` | Build a severity-ordered remediation plan from the last audit |
| `Which findings are suppressed?` | `ListSuppressed` | List suppressed findings from the last audit |
| `Set baseline` | `SetBaseline` | Save the last audit as a known-good baseline snapshot |
| `Check drift` | `CheckDrift` | Compare live config against the saved baseline and report new/worsened findings |
| `Show baseline` | `ShowBaseline` | Display the active baseline findings for the last audit intent |
| `Help` | `Help` | Returns supported agent capabilities |

## Data Sources

The agent reads local host state using common Linux tools:

| Scanner | Commands | Purpose |
| --- | --- | --- |
| `FirewallScanner` | `iptables -L -n -v`, fallback `nft list ruleset` | Reads firewall posture and rule text |
| `PortScanner` | `ss -tulnp`, fallback `netstat -tulnp` | Finds listening TCP/UDP ports and owning processes when visible |
| `ServiceScanner` | `systemctl list-units --type=service --state=running --no-pager --no-legend` | Finds running systemd services |
| `NetworkScanner` | `ip addr`, `ip route`, `ss -tunap` | Reads interfaces, routes, and active connections |
| `SshConfigScanner` | `sshd -T`, fallback `/etc/ssh/sshd_config` + includes | Reads SSH daemon hardening directives |

Scanner failures are reported as warnings instead of crashing the agent. Some commands may expose less detail without elevated privileges, especially process names, firewall rules, and `sshd -T` host key access.

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

## How The Pipeline Works

1. `QueryParser` converts the user query into an `AgentQuery` containing an `AgentIntent` and optional target reference.
2. `SecurityAgent` runs the required scanners with cancellation support.
3. `ScanDataBuilder` collects scanner output and data-source capability status into a thread-safe snapshot.
4. The rule policy provider resolves built-in role defaults and user overrides from `~/.config/VulcansTrace/policy.json`.
5. Rules matching the requested intent evaluate the snapshot, using contextual role parameters when they opt into `IContextualRule`.
6. Disabled rules are skipped, auto-pass rules are downgraded to passed results, and severity overrides are applied before findings are created.
7. Failed rules become `Finding` records with stable fingerprints derived from rule ID, category, source host, and target. Severity, timestamps, and description text are excluded so the same underlying issue can be tracked when its wording or severity changes.
8. `ExplanationProvider` fills markdown templates for each finding and parses them into structured explanation sections.
9. `SecurityAgent` remembers generated findings with their originating rule IDs so follow-up questions like `explain FW-001` can resolve without relying on text matching.
10. If raw log text is available, `SentryAnalyzer` can add log-derived findings.
11. Suppressions expired longer than the 30-day review retention window are pruned, active fingerprint-scoped suppressions are applied first, legacy rule-ID/target suppressions remain supported, and rule pass/fail/suppressed counts are added to `AgentResult`.
12. Baseline snapshots can be saved from any audit result. Each baseline stores lightweight `AuditSnapshotFinding` records for diff calculations and preserves the original `Finding` objects for lossless display. Baselines are intent-scoped and persisted to the user config directory; the active baseline per intent is used by `CheckDrift` to compare live state against the known-good snapshot via `AuditDiffCalculator`.
13. `AgentReportGenerator` can merge agent findings and log findings into an `AnalysisResult`; exported CSV, JSON, Markdown, HTML, and STIX evidence preserves agent rule IDs, fingerprints, data-source capability reports, and active suppression notes when present.

## Rule Tuning

The agent supports local role-aware policy for `Workstation`, `Server`, `LabBox`, `Router`, and `DevMachine` profiles. Built-in defaults tune selected rules, and user JSON policies take precedence while inheriting built-in parameters that are not overridden.

The policy file lives at `~/.config/VulcansTrace/policy.json`. It can disable a rule, auto-pass a rule, override severity, or provide rule-specific parameters. Current contextual rules include `PORT-001`, `PORT-002`, `SRV-005`, and `SSH-007`.

The Avalonia composition currently runs the agent as `Workstation`; other roles are available through the agent API and policy provider wiring until a role selector is added.

## Explanation Behavior

The agent supports three explanation paths:

- **Selected finding:** if the user selects a finding in the UI and asks `explain this finding`, `AgentViewModel` calls `ExplainFindingAsync` directly without re-scanning.
- **Previous agent finding:** after an audit, references such as `explain FW-001`, `explain firewall`, or `explain SSH` are resolved against cached agent findings.
- **Known rule ID with no cached finding:** if a rule ID is recognized but no previous finding is available, the agent runs that single rule and explains the result if it fails.

When no selected finding or target reference is available, the agent returns guidance instead of running an unrelated full audit.

Explanations are rendered as structured sections: what was found, why it matters, how to verify, preconditions, backup commands, suggested next action, rollback commands, confidence, and caveats. The UI extracts copyable commands only from the verification section and labels them with a heuristic safety classification plus structural badges for sudo usage, command chains, pipes, redirects, and download-and-execute patterns. Suggested action commands are kept in the explanation/remediation preview path, safety-labeled in exported remediation plans with the same structural warnings, and never applied automatically.

## UI Integration

The Avalonia application exposes the agent in a collapsible Security Agent panel. The panel supports:

- Chat-style natural-language questions.
- Quick-action buttons for full audit, firewall, ports, services, network, selected-finding explanation, and audit export.
- Baseline quick-action buttons for **Set Baseline**, **Check Drift**, and **Show Baseline**.
- In-flight query cancellation.
- Data-source capability messages showing whether scanner inputs such as iptables, nftables, ss, netstat, ip, and systemctl were available, unavailable, permission-limited, or not checked.
- Agent findings grouped by category with compact severity summaries.
- Chat filters for severity and category that hide/show finding groups without changing the underlying audit result.
- A Coverage tab after agent audits with totals and category breakdowns for passed, active failed, suppressed, and crashed rule checks.
- Two-way selection tracking from the findings grid for selected-finding explanations; the Explain Selected action is only enabled when a finding is selected.
- Agent audit results are loaded into the shared findings grid so they can be selected, explained, exported, or suppressed.
- An elevated-privilege warning banner when scanner output indicates permission-limited visibility.
- Role-aware rule tuning through local policy, currently wired as `Workstation` in the desktop UI.
- Audit history persisted to the user config directory when available, capped at 50 lightweight snapshots by default, with compare-last-two, selectable before/after comparison, deterministic narrative diff summaries, and exported-state tracking after successful evidence export. If persistence fails, the UI reports that history is session-only.
- Configuration baselines persisted to the user config directory (`~/.config/VulcansTrace/baselines.json`) when available, with in-memory fallback. Baselines are intent-scoped; each intent has one active baseline at a time. Drift detection re-runs the audit and compares against the active baseline, surfacing new and worsened findings.
- Accept Risk suppressions by finding fingerprint when available, with legacy rule-ID/target matching for older entries. Suppressions can last 7 days, 30 days, 90 days, or permanently. Expired suppressions stop applying immediately, remain in the review queue for 30 days, and are pruned after that retention window. Suppressions are persisted to the user config directory when available; if persistence fails, the UI reports that suppressions are session-only.
- A Suppressions tab with friendly filter labels, review counts, status badges, and row actions to renew, convert duration, edit reason, or remove suppressions.
- Export Audit support that reuses the shared evidence export flow for the latest agent audit and includes active suppression notes when present.
- Export Remediation support that writes a review-only markdown plan with preconditions, backup/apply/rollback command sections, safety notes, rollback hints, and verification commands. Plans with risky or unclassified apply/backup commands are blocked from standalone export and omitted from evidence bundles unless the template includes explicit rollback guidance.
- Automatic sharing of the main log input with the agent so pasted firewall logs can be included in agent analysis.

## Privacy And Safety

- The agent is local-only.
- It does not make network calls for analysis.
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
| SSH-001 | CIS 5.4 — Restrict Administrator Privileges | 5.2.7 — Ensure SSH root login is disabled |
| SSH-002 | CIS 6.3 — Require MFA for Externally-Exposed Applications | 5.2.16 — Ensure SSH PasswordAuthentication is disabled |
| SSH-003 | CIS 6.3 — Require MFA for Externally-Exposed Applications | 5.2.14 — Ensure SSH MaxAuthTries is configured |
| SSH-004 | CIS 4.8 — Uninstall or Disable Unnecessary Services | 5.2.15 — Ensure SSH Protocol is set to 2 |
| SSH-005 | CIS 5.2 — Use Unique Passwords | 5.2.9 — Ensure SSH PermitEmptyPasswords is disabled |
| SSH-006 | CIS 6.3 — Require MFA for Externally-Exposed Applications | 5.2.17 — Ensure SSH PubkeyAuthentication is enabled |
| SSH-007 | CIS 4.8 — Uninstall or Disable Unnecessary Services | 5.2.12 — Ensure SSH X11 forwarding is disabled |
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

The remaining rules (NET-001 through NET-004, PORT-001, PORT-004, SRV-003) map to CIS Controls v8 where no direct Ubuntu benchmark section exists.

Mappings are defined on `IRule.CisMappings`, flow through `RuleResult.CisMappings`, and are attached to `Finding.CisMappings` in both the full audit and single-rule explain paths. Evidence exports preserve them in CSV, HTML, Markdown, JSON, and STIX formats.

## Current Limitations

- It is a deterministic rule-based assistant, not an LLM-backed conversational system.
- Scanner parsers are pragmatic and command-output based, so unusual distro output may need parser tests and adjustments.
- Capability status reports command availability and permission visibility, not semantic completeness of every data source.
- Some findings are posture checks rather than proof of compromise.
- Process names and firewall details may require elevated privileges depending on the host.
- Deterministic follow-up questions (changes, critical explanations, category filtering, remediation prioritization, and suppressed listing) operate on the last audit result without re-running scans. They require a prior audit context; when context is missing they return guidance or fall back to a targeted audit for category-filter queries.
- New suppressions are fingerprint-scoped when the selected finding has a fingerprint. Older suppressions without fingerprints still match by rule ID and target, so intentional target text changes can require accepting the risk again.
- Command safety labels use conservative keyword heuristics. Unknown means "not classified," not "safe."
- The desktop UI currently uses the `Workstation` role by default; changing roles requires code-level composition until a role selector is added.

## Roadmap

- Add richer follow-up explanation flows that can compare related findings and suggest next triage steps.
- Add a machine-role selector and policy editing surface in the Avalonia UI.
- Expand scanner fixtures across more distributions and command variants.
- Add reminder surfaces for upcoming suppression review dates.

## Implementation Evidence

- [SecurityAgent.cs](../VulcansTrace.Linux.Agent/SecurityAgent.cs)
- [QueryParser.cs](../VulcansTrace.Linux.Agent/Query/QueryParser.cs)
- [ScanData.cs](../VulcansTrace.Linux.Agent/Scanners/ScanData.cs)
- [FirewallScanner.cs](../VulcansTrace.Linux.Agent/Scanners/FirewallScanner.cs)
- [PortScanner.cs](../VulcansTrace.Linux.Agent/Scanners/PortScanner.cs)
- [ServiceScanner.cs](../VulcansTrace.Linux.Agent/Scanners/ServiceScanner.cs)
- [NetworkScanner.cs](../VulcansTrace.Linux.Agent/Scanners/NetworkScanner.cs)
- [SshConfigScanner.cs](../VulcansTrace.Linux.Agent/Scanners/SshConfigScanner.cs)
- [Security rules](../VulcansTrace.Linux.Agent/Rules/SecurityRules)
- [AgentViewModel.cs](../VulcansTrace.Linux.Avalonia/ViewModels/AgentViewModel.cs)
- [SecurityAgentTests.cs](../VulcansTrace.Linux.Tests/Agent/SecurityAgentTests.cs)
- [ScannerParserFixtureTests.cs](../VulcansTrace.Linux.Tests/Agent/ScannerParserFixtureTests.cs)
- [BaselineEntry.cs](../VulcansTrace.Linux.Agent/Baselines/BaselineEntry.cs)
- [IBaselineStore.cs](../VulcansTrace.Linux.Agent/Baselines/IBaselineStore.cs)
- [JsonFileBaselineStore.cs](../VulcansTrace.Linux.Agent/Baselines/JsonFileBaselineStore.cs)
- [BaselineDiffResult.cs](../VulcansTrace.Linux.Agent/Baselines/BaselineDiffResult.cs)
