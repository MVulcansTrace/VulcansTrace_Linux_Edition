## K8S-001

**What we found:** Kubernetes pod(s) run privileged containers: {{pods}}.

**Why this matters:** Privileged containers bypass many runtime isolation controls and can become a direct path from pod compromise to host compromise.

**How to verify:**
1. Inspect pod security contexts: `kubectl get pod -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{" "}{.spec.containers[*].securityContext.privileged}{"\n"}{end}'`
2. Review workload manifests for `securityContext.privileged: true`

**Suggested next action:** Remove privileged mode and grant only the specific capabilities, devices, or host paths the workload requires.

**Risk level:** CRITICAL

**Confidence / caveat:** High confidence when kubectl returns pod JSON for the configured context.

## K8S-002

**What we found:** Kubernetes pod(s) share host namespaces: {{pods}}.

**Why this matters:** `hostNetwork`, `hostPID`, and `hostIPC` reduce pod isolation and can expose host networking, processes, or IPC resources to compromised workloads.

**How to verify:**
1. Check namespace sharing: `kubectl get pod -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{" hostNetwork="}{.spec.hostNetwork}{" hostPID="}{.spec.hostPID}{" hostIPC="}{.spec.hostIPC}{"\n"}{end}'`
2. Review workload manifests for host namespace settings

**Suggested next action:** Disable host namespace sharing unless there is a documented operational requirement.

**Risk level:** HIGH

**Confidence / caveat:** High confidence when kubectl returns pod JSON for the configured context.

## K8S-003

**What we found:** Kubernetes pod(s) contain containers that may run as root: {{pods}}.

**Why this matters:** Root inside a container increases impact if the workload is compromised, especially when combined with writable filesystems, added capabilities, or kernel vulnerabilities.

**How to verify:**
1. Check run-as settings: `kubectl get pod -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{" runAsNonRoot="}{.spec.securityContext.runAsNonRoot}{" runAsUser="}{.spec.securityContext.runAsUser}{"\n"}{end}'`
2. Review container-level `securityContext` overrides

**Suggested next action:** Set `runAsNonRoot: true` and use a nonzero `runAsUser` at pod or container scope.

**Risk level:** HIGH

**Confidence / caveat:** Conservative when neither `runAsUser` nor `runAsNonRoot` is set, because the image default user may be root.

## K8S-004

**What we found:** Kubernetes pod(s) have incomplete container security context hardening: {{pods}}.

**Why this matters:** Writable root filesystems, retained Linux capabilities, allowed privilege escalation, or unconfined seccomp profiles leave more room for runtime exploit chains.

**How to verify:**
1. Review security contexts: `kubectl get pod -A -o json`
2. Check for `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `capabilities.drop: ["ALL"]`, and a confined seccomp profile

**Suggested next action:** Harden each container security context and prefer `seccompProfile.type: RuntimeDefault`.

**Risk level:** MEDIUM

**Confidence / caveat:** High confidence for explicit fields. Missing fields are flagged because Pod Security Standards expect workloads to declare restrictive settings.
