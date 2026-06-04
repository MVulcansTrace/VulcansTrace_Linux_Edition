## CTR-001

**What we found:** Privileged container(s) are running: {{containers}}.

**Why this matters:** Privileged containers can access host devices and kernel features that normally form the container isolation boundary.

**How to verify:**
1. List running containers: `docker ps`
2. Inspect a container: `docker inspect <container-name>`

**Suggested next action:** Recreate the workload without `--privileged` and grant only the specific capabilities, devices, or mounts it requires.

**Risk level:** CRITICAL

**Confidence / caveat:** High confidence when Docker inspect data is available. If inspect failed, the scanner may have less detail.

## CTR-002

**What we found:** Container image(s) use the `latest` tag or no explicit tag: {{containers}}.

**Why this matters:** The `latest` tag is mutable. The same deployment can pull different code over time, making rollbacks and forensic reconstruction unreliable.

**How to verify:**
1. List running images: `docker ps`
2. Check deployment manifests or compose files for `:latest`

**Suggested next action:** Pin images to an explicit version or digest and document the update process.

**Risk level:** HIGH

**Confidence / caveat:** High confidence for running containers reported by Docker or crictl.

## CTR-003

**What we found:** Docker socket exposure detected: {{detail}}.

**Why this matters:** Access to `/var/run/docker.sock` is effectively root-equivalent on most Docker hosts because it can create privileged containers or mount host paths.

**How to verify:**
1. Check host socket: `ls -l /var/run/docker.sock`
2. Find socket mounts: `docker inspect <container-name> | grep docker.sock`

**Suggested next action:** Remove Docker socket mounts from workloads and restrict membership in the `docker` group to trusted administrators.

**Risk level:** CRITICAL

**Confidence / caveat:** High confidence when the socket exists or Docker inspect reports a socket mount.

## CTR-004

**What we found:** Containerd is using only the default namespace without explicit isolation.

**Why this matters:** Separating workloads into explicit containerd namespaces improves operational isolation and makes policy, inventory, and incident response clearer.

**How to verify:**
1. List namespaces: `ctr namespace ls`
2. Review workload runtime configuration for namespace usage

**Suggested next action:** Move workloads into explicit namespaces that match environment, tenant, or application boundaries.

**Risk level:** MEDIUM

**Confidence / caveat:** Medium confidence. Some simple single-workload hosts intentionally use only the default namespace.

## CTR-005

**What we found:** Container image(s) reference known risky base-image hints: {{containers}}.

**Why this matters:** End-of-life base images stop receiving security fixes. Derived images can inherit vulnerable packages even when the application layer is current.

**How to verify:**
1. Inspect local image metadata: `docker inspect <image>`
2. Check image labels such as `org.opencontainers.image.base.name`

**Suggested next action:** Rebuild the image from a supported base image and pin the new base to a maintained version or digest.

**Risk level:** HIGH

**Confidence / caveat:** Moderate confidence. This check is offline and deterministic; it uses local image references and base-image labels rather than a live vulnerability feed.
