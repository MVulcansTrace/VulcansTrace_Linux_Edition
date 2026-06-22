# Cross-Scanner Validation Coverage Table

This table documents the Phase 1 cross-scanner validation coverage for all **Critical** and **High** severity rules.

- **Validated** — the finding is checked against an independent scanner data source (e.g. a firewall rule is verified by a port scanner, an SSH config finding is verified by service/port scanners).
- **Limited** — a validator exists, but it relies on the same scanner source as the rule or only provides a weak corroborating signal. It still adds an evidence signal but is not a true independent cross-check.
- **No independent cross-check** — no second independent scanner exists for this category, so cross-scanner validation is not performed.

Medium rules are intentionally out of scope for Phase 1 and will be addressed in Phase 2.

## Validated (independent cross-check)

| Rule | Category | Severity | Independent Sources | Validation Logic |
|------|----------|----------|---------------------|------------------|
| FW-002 | Firewall | High | `ss` / `netstat`, `ip addr` | Confirms SSH is reachable: port 22 is listening on a public address and a non-loopback interface is up. |
| PORT-003 | Port | Critical | `iptables` / `nftables` | Confirms a firewall ACCEPT or block rule exists for the reported database port, or that no firewall is active. |
| SRV-001 | Service | Critical | `ss` / `netstat` | Confirms the Telnet service finding by checking for a listener on port 23. |
| SRV-002 | Service | High | `ss` / `netstat` | Confirms the FTP service finding by checking for a listener on ports 20 or 21. |
| SRV-004 | Service | Critical | `ss` / `netstat` | Confirms the legacy r-services finding by checking for listeners on ports 512, 513, or 514. |
| SSH-001 | SSH | Critical | `systemctl`, `ss` / `netstat` | Confirms the SSH config finding by checking that an SSH service is running and port 22 is listening. |
| SSH-002 | SSH | High | `systemctl`, `ss` / `netstat` | Same as SSH-001: verifies SSH is reachable before raising confidence in the config finding. |
| SSH-004 | SSH | Critical | `systemctl`, `ss` / `netstat` | Same as SSH-001. |
| SSH-005 | SSH | Critical | `systemctl`, `ss` / `netstat` | Same as SSH-001. |
| SSH-006 | SSH | High | `systemctl`, `ss` / `netstat` | Same as SSH-001. |
| USER-001 | User Account | Critical | `systemctl`, `ss` / `netstat` | Confirms that an additional UID-0 account has a reachable SSH path (service + port 22). |

## Limited (same-source or weak corroboration)

| Rule | Category | Severity | Source | Notes |
|------|----------|----------|--------|-------|
| NET-002 | Network | High | `ss -tunap` | Confirms active connections are observable on the host, but does not independently verify the specific suspicious connection reported. |

## No independent cross-check

| Rule | Category | Severity | Reason |
|------|----------|----------|--------|
| CRON-001 | Cron | High | No independent cron-job scanner exists; the rule reads crontabs directly. |
| CRON-002 | Cron | High | No independent cron-job scanner exists. |
| FILE-001 | File Permission | High | No independent file-permission scanner exists; the rule reads `ls`/`stat` output directly. |
| FILE-003 | File Permission | High | No independent file-permission scanner exists. |
| FILE-004 | File Permission | High | No independent file-permission scanner exists. |
| FILE-005 | File Permission | High | No independent file-permission scanner exists. |
| FSYS-002 | Filesystem Audit | High | No independent filesystem scanner exists; the rule walks the filesystem directly. |
| FSYS-004 | Filesystem Audit | High | No independent filesystem scanner exists. |
| FW-001 | Firewall | High | Only the firewall scanner can report the default INPUT policy; no independent source exists. |
| FW-004 | Firewall | Critical | The rule *is* the firewall-active check; validating it with itself would be circular. |
| KERN-001 | Kernel Hardening | High | No independent kernel-parameter scanner exists; the rule reads `/proc/sys` and EFI variables directly. |
| KERN-002 | Kernel Hardening | High | No independent kernel-parameter scanner exists. |
| LOG-002 | Logging/Audit | High | No independent logging scanner exists; the rule reads service status and config files directly. |
| LOG-003 | Logging/Audit | High | No independent logging scanner exists. |
| LOG-006 | Logging/Audit | High | No independent logging scanner exists. |
| NET-003 | Network | High | Only the interface scanner can report whether an interface is up; no independent source exists. |
| CTR-001 | Container | Critical | No independent container posture scanner exists; the rule reads the same `docker`/`crictl` data a validator would use. |
| CTR-002 | Container | High | No independent container scanner exists; uses the same container image metadata source. |
| CTR-003 | Container | Critical | No independent container runtime scanner exists; uses the same `docker.sock`/`docker inspect` data. |
| CTR-005 | Container | High | No independent container image scanner exists; uses the same container scanner data. |
| K8S-001 | Kubernetes | Critical | No independent Kubernetes scanner exists; the rule reads the same `kubectl` pod data. |
| K8S-002 | Kubernetes | High | No independent Kubernetes scanner exists; uses the same pod security context data. |
| K8S-003 | Kubernetes | High | No independent Kubernetes scanner exists; uses the same pod/container data. |
| PKG-VULN-001 | Package Vulnerability | High | No independent package scanner exists; the rule reads package manager data directly. |
| PKG-VULN-003 | Package Vulnerability | Critical | No independent package scanner exists. |
| PROC-001 | Process Runtime | Critical | No independent runtime process scanner exists; the rule reads `/proc` directly. |
| PROC-002 | Process Runtime | High | No independent runtime process scanner exists. |
| PROC-003 | Process Runtime | High | No independent runtime process scanner exists. |
| PROC-005 | Process Runtime | High | No independent runtime process scanner exists. |
| PROC-006 | Process Runtime | Critical | No independent runtime process scanner exists. |
| USER-002 | User Account | Critical | No independent password-hash scanner exists; the rule reads `/etc/shadow` directly. |
| USER-006 | User Account | High | No independent account scanner exists; the rule reads `/etc/passwd` directly. |
| USER-010 | User Account | High | No independent PAM scanner exists; the rule reads PAM stack files directly. |
| YARA-001 | YARA | High | No independent YARA scanner exists; the rule runs YARA directly. |

## Summary

| Status | Count | Notes |
|--------|-------|-------|
| Validated | 11 | Strong independent cross-check using a separate scanner data source. |
| Limited | 1 | Weak corroboration only (`NET-002`). |
| No independent cross-check | 37 | No feasible independent scanner is available for these categories in Phase 1, including container/Kubernetes rules where validation would be tautological. |

## Implementation Notes

- Validation is intentionally scoped to **Critical** and **High** severity rules in Phase 1.
- Medium rules (e.g. `PORT-002`, `SRV-003`, `FW-003`, `SSH-003`, `SSH-007`, `FSYS-001`, `FSYS-003`, `FSYS-005`, `LOG-001`, `LOG-005`, `LOG-007`, `USER-003`, `USER-004`, `USER-008`, `USER-009`, `NET-001`, `NET-004`, `CRON-003`, `CTR-004`, `K8S-004`) are deferred to Phase 2.
- Validation never downgrades a finding below **Unknown** or raises it above **High** unless it was already **Confirmed**.
- A failed validator predicate produces a warning but never crashes the audit.
