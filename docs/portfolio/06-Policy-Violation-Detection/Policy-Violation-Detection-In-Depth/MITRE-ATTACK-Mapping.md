# Policy Violation Detection — MITRE ATT&CK Mapping

## Technique Mapping

| MITRE Technique | ID | Tactic | How Detected | Coverage |
|---|---|---|---|---|
| Application Layer Protocol: Web Protocols | T1071.001 | Command and Control (TA0011) | Indirect — HTTP/HTTPS not in disallowed list | None |
| Application Layer Protocol: File Transfer | T1071.002 | Command and Control (TA0011) | Direct — FTP (port 21) is disallowed | Direct |
| Application Layer Protocol: Mail Protocols | T1071.003 | Command and Control (TA0011) | Indirect — SMTP not in default list | Partial |
| Application Layer Protocol: DNS | T1071.004 | Command and Control (TA0011) | None — DNS not in disallowed list | None |
| Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol | T1048.003 | Exfiltration (TA0010) | Direct — FTP and Telnet are unencrypted | Direct |
| Exfiltration (Parent Tactic) | TA0010 | — | All outbound connections on disallowed ports | Broad |

---

## Attack Lifecycle

```
 Initial Access          Persistence          Privilege Escalation
 ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
 │ T1190 Exploit│   │ T1053 Sched  │   │ T1078 Valid  │
 │  Public-Face │──>│  Task        │──>│  Accounts    │
 └──────────────┘   └──────────────┘   └──────┬───────┘
                                                │
                     Defense Evasion            │
                     ┌──────────────┐           │
                     │ T1071 App    │<──────────┤
                     │  Layer Proto │           │
                     └──────┬───────┘           │
                            │                   │
                            v                   v
                     ┌──────────────────────────────────┐
                     │        EXFILTRATION               │  <== DETECTED HERE
                     │   T1048 Over Alternative Protocol │
                     │   FTP (21), Telnet (23), SMB (445)│
                     └──────────────────────────────────┘
```

The policy violation detector operates at the **final phase** of the kill chain — detecting data as it leaves the organization. This is the last opportunity to catch the attack before data is lost.

---

## Detection Gaps

| Gap | Description | Risk Level |
|---|---|---|
| T1048.001 Exfiltration Over Symmetric Encrypted Channel | SSH/SFTP exfiltration not on default disallowed list | Medium |
| T1048.002 Exfiltration Over Asymmetric Encrypted Channel | HTTPS exfiltration — port 443 is allowed | High |
| T1048.003 Exfiltration Over Unencrypted Protocol | Partially covered — only FTP/Telnet, not all unencrypted protocols | Low |
| T1071.001 Web Protocols | HTTPS C2 communication is invisible | High |
| T1071.004 DNS | DNS tunneling and exfiltration are invisible | High |

---

## Security Takeaways

- The detector directly covers FTP-based exfiltration (T1048.003) and FTP/Telnet command-and-control (T1071.002)
- The most significant gaps are encrypted protocol abuse (HTTPS, SSH, DNS) — these require different detection strategies
- The detector is most effective against unsophisticated attackers and insider threats who use prohibited protocols without tunneling
- Layering with the beaconing detector, novelty detector, and external DPI tools provides comprehensive exfiltration coverage across the MITRE matrix
