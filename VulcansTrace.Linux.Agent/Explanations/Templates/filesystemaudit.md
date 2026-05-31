## FSYS-001

**What we found:** {{count}} world-writable file(s) exist outside expected temporary paths, starting with {{path}} (mode {{mode}}, owned by {{owner}}:{{group}}).

**Why this matters:** World-writable files allow any user to modify their contents. When found outside /tmp, /var/tmp, or /dev/shm, they often indicate misconfiguration, overly permissive package installers, or attacker-planted persistence. Any local user can overwrite the file to inject malicious code or alter behavior.

**How to verify:**
1. List world-writable files: `find / -xdev -type f -perm -002 -exec stat -c '%a %U %G %n' {} + 2>/dev/null`
2. Review each file's purpose and ownership.

**Backup commands:**
1. Document current permissions: `find / -xdev -type f -perm -002 -exec stat -c '%a %n' {} + > /tmp/world-writable-files.bak`

**Suggested next action:**
1. Remove world-write permission if not needed: `sudo chmod o-w {{path}}`
2. Or tighten ownership: `sudo chown root:root {{path}} && sudo chmod 644 {{path}}`
3. For shared data, use a dedicated group instead of world-writable.

**Rollback commands:**
1. Re-apply documented permissions manually if needed.

**Risk level:** MEDIUM

**Confidence / caveat:** High confidence — direct filesystem enumeration.

> These are suggestions only. Review commands before running them on your system.

## FSYS-002

**What we found:** {{count}} unexpected SUID/SGID binary(ies) found, starting with {{path}} (mode {{mode}}, owned by {{owner}}:{{group}}).

**Why this matters:** SUID/SGID binaries run with the privileges of the file owner or group. Attackers love dropping custom SUID shells or exploiting misconfigured ones for instant privilege escalation. Even legitimate binaries can be dangerous if they have vulnerabilities.

**How to verify:**
1. List all SUID/SGID binaries: `find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -exec ls -ld {} + 2>/dev/null`
2. Compare against your distribution's package manifest.

**Backup commands:**
1. Document current state: `find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -exec stat -c '%a %U %G %n' {} + > /tmp/suid-sgid-backup.txt`

**Suggested next action:**
1. Investigate whether {{path}} is legitimate: `dpkg -S {{path}}` or `rpm -qf {{path}}`
2. If not needed, remove the special bits: `sudo chmod u-s,g-s {{path}}`
3. If the binary is unknown, consider removing it entirely after investigation.

**Rollback commands:**
1. Restore SUID/SGID from backup if needed.

**Risk level:** HIGH

**Confidence / caveat:** High confidence. Verify against your distribution's whitelist before removing bits from system binaries.

> These are suggestions only. Review commands before running them on your system.

## FSYS-003

**What we found:** {{count}} unowned file(s) found, starting with {{path}} (mode {{mode}}, owner {{owner}}, group {{group}}).

**Why this matters:** Files with no valid owner or group often appear after user deletion without cleanup, package corruption, or attacker activity. They complicate accountability and may hide malicious content that doesn't appear in normal user-owned file listings.

**How to verify:**
1. List unowned files: `find / -xdev \( -nouser -o -nogroup \) -type f -exec ls -ld {} + 2>/dev/null`
2. Check if the numeric UID/GID maps to a former user.

**Backup commands:**
1. Document findings: `find / -xdev \( -nouser -o -nogroup \) -type f -exec stat -c '%a %U %G %n' {} + > /tmp/unowned-files.bak`

**Suggested next action:**
1. Reassign ownership if the file is legitimate: `sudo chown root:root {{path}}`
2. If the file is unknown or suspicious, move it to quarantine for review.
3. Remove if clearly unnecessary: `sudo rm {{path}}`

**Rollback commands:**
1. Restore ownership from backup notes if needed.

**Risk level:** MEDIUM

**Confidence / caveat:** High confidence. Numeric UIDs/GIDs for deleted users are correctly reported as unowned.

> These are suggestions only. Review commands before running them on your system.

## FSYS-004

**What we found:** {{count}} world-writable dir(s) without the sticky bit found, starting with {{path}} (mode {{mode}}, owned by {{owner}}:{{group}}).

**Why this matters:** The sticky bit (1xxx) on a world-writable directory restricts deletion and renaming to the file owner, directory owner, or root. Without it, any user can delete or replace files created by others. /tmp relies on this protection; missing sticky bits elsewhere create similar risks.

**How to verify:**
1. Find affected directories: `find / -xdev -type d -perm -002 ! -perm -1000 -exec ls -ld {} + 2>/dev/null`
2. Check specific directory: `ls -ld {{path}}`

**Backup commands:**
1. Document current permissions: `find / -xdev -type d -perm -002 ! -perm -1000 -exec stat -c '%a %n' {} + > /tmp/sticky-bit-backup.txt`

**Suggested next action:**
1. Add the sticky bit: `sudo chmod +t {{path}}`
2. If the directory should not be world-writable, tighten permissions: `sudo chmod 755 {{path}}`

**Rollback commands:**
1. Remove sticky bit if needed: `sudo chmod -t {{path}}`

**Risk level:** HIGH

**Confidence / caveat:** High confidence.

> These are suggestions only. Review commands before running them on your system.

## FSYS-005

**What we found:** /tmp is mounted with options `{{options}}` but is missing `{{missing}}`.

**Why this matters:** /tmp is world-writable and frequently used by attackers to stage exploits, compile payloads, and create device nodes. Mounting it with noexec prevents binary execution, nosuid prevents privilege escalation via SUID binaries, and nodev prevents device file creation. Together they form a critical containment layer.

**How to verify:**
1. Check current mount options: `findmnt -n -o OPTIONS /tmp` or `mount | grep 'on /tmp'`
2. Review /etc/fstab for persistent configuration.

**Backup commands:**
1. Back up /etc/fstab: `sudo cp /etc/fstab /etc/fstab.bak.$(date +%s)`

**Suggested next action:**
1. Edit /etc/fstab to add missing options to the /tmp line: `noexec,nosuid,nodev`
2. Example fstab entry: `tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev,size=2G 0 0`
3. Re-mount: `sudo mount -o remount,noexec,nosuid,nodev /tmp`

**Rollback commands:**
1. Restore /etc/fstab from backup: `sudo cp /etc/fstab.bak.* /etc/fstab`
2. Re-mount with old options: `sudo mount -a`

**Risk level:** MEDIUM

**Confidence / caveat:** High confidence. Some legacy applications may expect to execute from /tmp; test thoroughly after adding noexec.

> These are suggestions only. Review commands before running them on your system.
