# Lateral Movement Detection — MITRE ATT&CK Mapping

## Technique Mapping

| MITRE Technique | ID | Tactic | How Detected | Coverage |
|---|---|---|---|---|
| Remote Services: SMB/Windows Admin Shares | T1021.002 | Lateral Movement (TA0008) | SMB port 445 connections to multiple internal hosts | Port-based |
| Remote Services: Remote Desktop Protocol | T1021.001 | Lateral Movement (TA0008) | RDP port 3389 connections to multiple internal hosts | Port-based |
| Remote Services: SSH | T1021.004 | Lateral Movement (TA0008) | SSH port 22 connections to multiple internal hosts | Port-based |
| Windows Management Instrumentation | T1047 | Execution (TA0002) | Indirect — WMI uses port 135 (DCOM) or 5985/5986 (WinRM), neither in default admin ports | Partial |
| Command and Scripting Interpreter | T1059 | Execution (TA0002) | Indirect — SSH (port 22) may carry script-based pivoting | Partial |
| Lateral Movement (Parent Tactic) | TA0008 | — | All admin-port internal pivoting patterns | Broad |

---

## Attack Lifecycle

```
 Initial Access          Execution           Persistence        Privilege Escalation
 ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
 │ T1566 Phish  │──>│ T1059 Script │──>│ T1053 Sched  │──>│ T1078 Creds  │
 └──────────────┘   └──────────────┘   └──────────────┘   └──────┬───────┘
                                                                │
                 Defense Evasion       ┌─────────────────────────┘
                 ┌──────────────┐      │
                 │ T1070 Logs   │<─────┤
                 └──────────────┘      │
                                       v
                            ┌──────────────────────┐
                            │   LATERAL MOVEMENT   │  <== DETECTED HERE
                            │   T1021 Remote Svc   │
                            │   T1047 WMI          │
                            └──────────┬───────────┘
                                       │
              Collection          ┌─────┴──────────┐
              ┌──────────────┐   │  Command &      │
              │ T1005 Data   │<──│  Control (C2)   │
              └──────┬───────┘   └────────────────┘
                     │
                     v
              ┌──────────────┐
              │ T1041 Exfil  │
              │  Over C2     │
              └──────────────┘
```

The lateral movement detector operates at the pivot point where the attacker transitions from controlling a single host to compromising additional internal systems. This is typically a **mid-chain phase** in the kill chain.

---

## Detection Gaps

| Gap | Description | Risk Level |
|---|---|---|
| Remote Services: VNC (T1021.005) | Port 5900 not in lateral movement detector's default admin ports (monitored by privilege escalation detector) | Medium |
| Remote Services: Distributed Component Object Model (T1021.003) | DCOM uses port 135 (RPC), which is not in the default admin ports | Medium |
| Application Deployment Software | Tools like PsExec may use different ports | Low |
| Pass-the-Hash / Pass-the-Ticket | Credential-based attacks produce same logs as legitimate access | High |

---

## Security Takeaways

- The detector covers traffic on the three most common lateral movement ports (445/SMB, 3389/RDP, 22/SSH) corresponding to MITRE T1021 sub-techniques — detection is port-based, not protocol-aware
- Scripting (T1059) over SSH (port 22) produces traffic visible to the detector, but without payload inspection the detector cannot distinguish malicious scripting from legitimate admin SSH sessions
- The primary detection gap is credential-based lateral movement that is indistinguishable from legitimate admin traffic at the network level
- Layering this detector with endpoint detection (process monitoring, credential usage) significantly improves coverage of MITRE lateral movement techniques
