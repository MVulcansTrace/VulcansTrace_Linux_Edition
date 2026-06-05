/*
   VulcansTrace bundled Linux YARA rules.
   These rules are intentionally conservative and focus on common
   static indicators seen in Linux malware families and packed binaries.
   Users can extend detection by dropping custom .yar files into:
     ~/.config/VulcansTrace/yara/
*/

rule Linux_ELF_UPX
{
    meta:
        description = "Detects UPX-packed ELF binaries"
        author = "VulcansTrace"
        severity = "medium"

    strings:
        $upx_magic = { 55 50 58 21 }
        $upx_str = "UPX!"
        $upx_url = "www.upx.org"

    condition:
        uint32(0) == 0x464c457f and any of them
}

rule Linux_SUID_Shell_Backdoor
{
    meta:
        description = "Detects SUID ELF binaries with common shell backdoor strings"
        author = "VulcansTrace"
        severity = "high"

    strings:
        $sh = "/bin/sh" ascii wide
        $su = "setuid(0)" ascii wide
        $sg = "setgid(0)" ascii wide

    condition:
        uint32(0) == 0x464c457f and all of them
}

rule Linux_Mirai_Generic
{
    meta:
        description = "Generic Mirai-related string indicators"
        author = "VulcansTrace"
        severity = "high"

    strings:
        $a = "MIRAI" ascii wide fullword
        $b = "/dev/watchdog" ascii
        $c = "killer" ascii wide fullword

    condition:
        uint32(0) == 0x464c457f and 2 of them
}

rule Linux_Suspicious_Shell_Script
{
    meta:
        description = "Detects suspicious patterns in non-ELF shell scripts (e.g., cron scripts)"
        author = "VulcansTrace"
        severity = "medium"

    strings:
        $reverse_shell = "/dev/tcp/" ascii
        $base64_pipe = "base64 -d" ascii
        $eval = "eval $(" ascii
        $pipe_bash = "| bash" ascii
        $pipe_sh = "| sh" ascii
        $bash_i = "bash -i" ascii

    condition:
        not uint32(0) == 0x464c457f and
        filesize < 50KB and
        2 of them
}
