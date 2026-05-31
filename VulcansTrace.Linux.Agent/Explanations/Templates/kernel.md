## KERN-001

**What we found:** kernel.randomize_va_space is set to {{value}}.

**Why this matters:** ASLR randomizes memory addresses so attackers cannot predict where code or data resides. A value of 0 disables ASLR entirely; 1 enables it for stack and VDSO but not heap; 2 enables full ASLR including heap. Without full ASLR, memory corruption exploits become significantly easier.

**How to verify:**
1. Check current value: `sysctl kernel.randomize_va_space`
2. Or read directly: `cat /proc/sys/kernel/randomize_va_space`

**Suggested next action:**
1. Temporarily set: `sudo sysctl -w kernel.randomize_va_space=2`
2. Make persistent by adding to `/etc/sysctl.conf` or `/etc/sysctl.d/99-aslr.conf`:
   ```
   kernel.randomize_va_space = 2
   ```
3. Apply: `sudo sysctl -p /etc/sysctl.d/99-aslr.conf`

**Risk level:** HIGH

**Confidence / caveat:** High confidence — this is a direct kernel parameter read. Some legacy applications may have compatibility issues with full ASLR; test before enforcing in production.

> These are suggestions only. Review commands before running them on your system.

## KERN-002

**What we found:** {{issues}}

**Why this matters:** IP forwarding turns the host into a router. Unless this system is explicitly a gateway or router, forwarding is unnecessary and can be exploited for traffic redirection, lateral movement, and network pivoting.

**How to verify:**
1. Check IPv4: `sysctl net.ipv4.ip_forward`
2. Check IPv6: `sysctl net.ipv6.conf.all.forwarding`

**Suggested next action:**
1. Disable IPv4 forwarding: `sudo sysctl -w net.ipv4.ip_forward=0`
2. Disable IPv6 forwarding: `sudo sysctl -w net.ipv6.conf.all.forwarding=0`
3. Make persistent in `/etc/sysctl.d/99-ipforward.conf`:
   ```
   net.ipv4.ip_forward = 0
   net.ipv6.conf.all.forwarding = 0
   ```
4. Apply: `sudo sysctl -p /etc/sysctl.d/99-ipforward.conf`

**Risk level:** HIGH

**Confidence / caveat:** High confidence. If this host is a router or VPN gateway, this is expected and should be suppressed or tuned via policy.

> These are suggestions only. Review commands before running them on your system.

## KERN-003

**What we found:** ICMP redirects are accepted (IPv4={{ipv4}}, IPv6={{ipv6}}).

**Why this matters:** ICMP redirects tell hosts to change their routing table. Attackers can forge these to redirect traffic through a compromised host, enabling man-in-the-middle attacks and traffic interception.

**How to verify:**
1. Check IPv4: `sysctl net.ipv4.conf.all.accept_redirects`
2. Check IPv6: `sysctl net.ipv6.conf.all.accept_redirects`

**Suggested next action:**
1. Disable IPv4 redirects: `sudo sysctl -w net.ipv4.conf.all.accept_redirects=0`
2. Disable IPv6 redirects: `sudo sysctl -w net.ipv6.conf.all.accept_redirects=0`
3. Make persistent in `/etc/sysctl.d/99-icmp.conf`:
   ```
   net.ipv4.conf.all.accept_redirects = 0
   net.ipv6.conf.all.accept_redirects = 0
   ```
4. Apply: `sudo sysctl -p /etc/sysctl.d/99-icmp.conf`

**Risk level:** MEDIUM

**Confidence / caveat:** High confidence. Very few modern networks rely on ICMP redirects for legitimate routing.

> These are suggestions only. Review commands before running them on your system.

## KERN-004

**What we found:** Source routed packets are accepted (value={{value}}).

**Why this matters:** Source routing lets the sender define the network path. Attackers use this to bypass firewalls, probe internal networks, and circumvent network segmentation controls.

**How to verify:**
1. Check current value: `sysctl net.ipv4.conf.all.accept_source_route`

**Suggested next action:**
1. Disable source routing: `sudo sysctl -w net.ipv4.conf.all.accept_source_route=0`
2. Make persistent in `/etc/sysctl.d/99-routing.conf`:
   ```
   net.ipv4.conf.all.accept_source_route = 0
   ```
3. Apply: `sudo sysctl -p /etc/sysctl.d/99-routing.conf`

**Risk level:** MEDIUM

**Confidence / caveat:** High confidence. Source routing is almost never needed in production networks.

> These are suggestions only. Review commands before running them on your system.

## KERN-005

**What we found:** Kernel module loading is unrestricted (kernel.modules_disabled={{value}}).

**Why this matters:** Unrestricted module loading allows attackers with root or physical access to load malicious kernel modules (rootkits, keyloggers, backdoors). Restricting it prevents runtime insertion of new kernel code.

**How to verify:**
1. Check current value: `sysctl kernel.modules_disabled`
2. Or: `cat /proc/sys/kernel/modules_disabled`

**Suggested next action:**
1. Restrict module loading: `sudo sysctl -w kernel.modules_disabled=1`
2. Make persistent in `/etc/sysctl.d/99-modules.conf`:
   ```
   kernel.modules_disabled = 1
   ```
3. Apply: `sudo sysctl -p /etc/sysctl.d/99-modules.conf`

**Caveats:** Setting this to 1 prevents loading any new modules until reboot. Ensure all required modules are loaded first (e.g., after boot and driver initialization). Setting to 2 makes it permanent for the current boot cycle.

**Risk level:** HIGH

**Confidence / caveat:** High confidence — direct parameter read. Verify that required hardware drivers are already loaded before applying.

> These are suggestions only. Review commands before running them on your system.

## KERN-006

**What we found:** Secure Boot is {{status}}.

**Why this matters:** Secure Boot uses UEFI firmware to verify cryptographic signatures on bootloaders, kernels, and kernel modules. Without it, boot-time malware (bootkits, rootkits) can load before the OS and evade detection.

**How to verify:**
1. Check with mokutil: `mokutil --sb-state`
2. Or check EFI variable: `hexdump -C /sys/firmware/efi/efivars/SecureBoot-*`

**Suggested next action:**
1. Enter firmware setup during boot (usually F2, F10, F12, or Del).
2. Navigate to Security or Boot settings.
3. Enable Secure Boot.
4. Ensure all boot components are signed, or enroll custom keys via mokutil if using unsigned kernels.

**Risk level:** MEDIUM

**Confidence / caveat:** Moderate confidence. Secure Boot requires UEFI and signed boot components. Some custom kernels, older hardware, or virtual machines may not support it. BIOS-based systems cannot use Secure Boot.

> These are suggestions only. Review commands before running them on your system.

## KERN-007

**What we found:** {{issues}} (kptr_restrict={{kptr_restrict}}, dmesg_restrict={{dmesg_restrict}}).

**Why this matters:** Kernel pointers exposed in /proc and dmesg give attackers the exact memory addresses they need to build reliable kernel exploits. Restricting them raises the bar for privilege escalation.

**How to verify:**
1. Check kptr_restrict: `sysctl kernel.kptr_restrict`
2. Check dmesg_restrict: `sysctl kernel.dmesg_restrict`

**Suggested next action:**
1. Set restrictions: `sudo sysctl -w kernel.kptr_restrict=2 && sudo sysctl -w kernel.dmesg_restrict=1`
2. Make persistent in `/etc/sysctl.d/99-kernel-exposure.conf`:
   ```
   kernel.kptr_restrict = 2
   kernel.dmesg_restrict = 1
   ```
3. Apply: `sudo sysctl -p /etc/sysctl.d/99-kernel-exposure.conf`

**Risk level:** MEDIUM

**Confidence / caveat:** High confidence. Some debugging tools may need unrestricted kernel pointers; use only on development systems.

> These are suggestions only. Review commands before running them on your system.
