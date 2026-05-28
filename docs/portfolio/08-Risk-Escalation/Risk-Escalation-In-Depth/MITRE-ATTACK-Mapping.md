# Risk Escalation — MITRE ATT&CK Mapping

How the risk escalation correlation rules map to the MITRE ATT&CK framework, showing defense-in-depth coverage across multiple tactics.

---

## Overview

The three correlation rules in `RiskEscalator` each span multiple MITRE ATT&CK tactics. When a rule fires, it means the analyst is looking at activity that crosses tactical boundaries — a strong indicator of a coordinated attack rather than isolated noise.

---

## Rule 1: Beaconing + LateralMovement

| Dimension | Mapping |
|-----------|---------|
| **Rule** | `categories.Contains("Beaconing") && categories.Contains("LateralMovement")` |
| **Source** | [RiskEscalator.cs:47](../../../../VulcansTrace.Linux.Engine/RiskEscalator.cs) |

### ATT&CK Techniques

| Tactic | Technique | ID | Relevance |
|--------|-----------|----|-----------|
| Command and Control | Non-Application Layer Protocol | T1095 | Beaconing detection identifies periodic C2 callbacks, often using custom protocols or standard protocols with abnormal timing |
| Command and Control | Application Layer Protocol | T1071 | Beaconing over HTTP/HTTPS (port 443, port 80) with regular intervals |
| Lateral Movement | Remote Services | T1021 | Lateral movement detection identifies connections to multiple internal hosts, often via SSH (port 22) or RDP (port 3389) |
| Lateral Movement | Internal Spearphishing | T1534 | Lateral movement may include connections to internal mail or file-sharing services |

### ATT&CK Tactics Covered

| Tactic | ID | Triggered By |
|--------|----|-------------|
| Command and Control | TA0011 | Beaconing finding |
| Lateral Movement | TA0008 | LateralMovement finding |

### Interpretation

A host exhibiting both C2 communication and lateral movement is a compromised machine under active attacker control. The Beaconing finding indicates an established command channel (TA0011), and the LateralMovement finding indicates the attacker is using that channel to pivot to other internal hosts (TA0008). This combination maps directly to the post-compromise phase of an advanced persistent threat.

---

## Rule 2: FlagAnomaly + PortScan

| Dimension | Mapping |
|-----------|---------|
| **Rule** | `categories.Contains("FlagAnomaly") && categories.Contains("PortScan")` |
| **Source** | [RiskEscalator.cs:51](../../../../VulcansTrace.Linux.Engine/RiskEscalator.cs) |

### ATT&CK Techniques

| Tactic | Technique | ID | Relevance |
|--------|-----------|----|-----------|
| Reconnaissance | Active Scanning | T1595 | Port scan detection identifies systematic probing of destination ports |
| Discovery | Network Service Discovery | T1046 | Port scanning maps available services on target hosts |
| Defense Evasion | Impair Defenses | T1562 | Flag anomalies (NULL, XMAS, FIN-only packets) are specifically designed to bypass IDS/IPS signature matching |

### ATT&CK Tactics Covered

| Tactic | ID | Triggered By |
|--------|----|-------------|
| Reconnaissance | TA0043 | PortScan finding |
| Discovery | TA0007 | PortScan finding |
| Defense Evasion | TA0005 | FlagAnomaly finding |

### Interpretation

An attacker combining reconnaissance with evasion is performing a sophisticated probe. The PortScan finding shows systematic service enumeration (TA0043/TA0007), and the FlagAnomaly finding shows the attacker is manipulating TCP flags to evade detection by network security devices (TA0005). This combination indicates a skilled operator, not an automated scanner.

---

## Rule 3: MacSpoofing + InterfaceHopping

| Dimension | Mapping |
|-----------|---------|
| **Rule** | `categories.Contains("MacSpoofing") && categories.Contains("InterfaceHopping")` |
| **Source** | [RiskEscalator.cs:53](../../../../VulcansTrace.Linux.Engine/RiskEscalator.cs) |

### ATT&CK Techniques

| Tactic | Technique | ID | Relevance |
|--------|-----------|----|-----------|
| Persistence | Valid Accounts | T1078 | MAC spoofing often accompanies credential-based attacks where the attacker assumes a legitimate network identity |
| Defense Evasion | Masquerading | T1036 | MAC address spoofing is a form of hardware identity masquerading |
| Command and Control | Non-Application Layer Protocol | T1095 | Interface hopping enables the attacker to use multiple network paths for C2, avoiding single-interface monitoring |

### ATT&CK Tactics Covered

| Tactic | ID | Triggered By |
|--------|----|-------------|
| Persistence | TA0003 | MacSpoofing finding (identity persistence) |
| Defense Evasion | TA0005 | MacSpoofing + InterfaceHopping findings |
| Command and Control | TA0011 | InterfaceHopping finding (multi-path C2) |

### Interpretation

An attacker manipulating both MAC addresses and network interfaces is attempting to bypass network access control (NAC) and monitoring systems. The MacSpoofing finding indicates the attacker is assuming different hardware identities (TA0005/T1036), and the InterfaceHopping finding indicates they are moving across network segments to avoid correlation (TA0011). This is a network-layer persistence and evasion pattern.

---

## Multi-Tactic Correlation Summary

The correlation rules span multiple MITRE ATT&CK tactics, demonstrating defense-in-depth:

```
Rule 1: Beaconing + LateralMovement
  TA0011 (Command and Control)  ─┐
                                  ├──> Critical escalation
  TA0008 (Lateral Movement)     ─┘

Rule 2: FlagAnomaly + PortScan
  TA0043 (Reconnaissance)       ─┐
  TA0007 (Discovery)            ─┼──> Critical escalation
  TA0005 (Defense Evasion)      ─┘

Rule 3: MacSpoofing + InterfaceHopping
  TA0003 (Persistence)          ─┐
  TA0005 (Defense Evasion)      ─┼──> Critical escalation
  TA0011 (Command and Control)  ─┘
```

| ATT&CK Tactic | Rules That Cover It |
|---------------|-------------------|
| TA0003 Persistence | Rule 3 |
| TA0005 Defense Evasion | Rule 2, Rule 3 |
| TA0007 Discovery | Rule 2 |
| TA0008 Lateral Movement | Rule 1 |
| TA0011 Command and Control | Rule 1, Rule 3 |
| TA0043 Reconnaissance | Rule 2 |

---

## ATT&CK Technique Reference

| Technique ID | Name | Detector |
|-------------|------|----------|
| T1078 | Valid Accounts | MacSpoofing (identity manipulation) |
| T1095 | Non-Application Layer Protocol | Beaconing (periodic C2 patterns) |
| T1595 | Active Scanning | PortScan (systematic port probing) |
| T1046 | Network Service Discovery | PortScan (service enumeration) |
| T1021 | Remote Services | LateralMovement (multi-host connections) |
| T1562 | Impair Defenses | FlagAnomaly (evasion packet crafting) |
| T1036 | Masquerading | MacSpoofing (hardware identity spoofing) |

---

## Security Takeaways

- Each correlation rule spans at least two MITRE ATT&CK tactics, meaning escalation fires only when an attacker's behavior crosses tactical boundaries — a strong indicator of coordinated activity rather than isolated noise
- The Beaconing + LateralMovement rule (TA0011 + TA0008) covers the classic post-compromise pattern: established C2 with internal pivoting, which is the most common behavior of advanced persistent threats
- The FlagAnomaly + PortScan rule (TA0043/TA0007 + TA0005) covers reconnaissance with active evasion, indicating a skilled operator rather than an automated tool
- The MacSpoofing + InterfaceHopping rule (TA0003 + TA0005 + TA0011) covers persistence and network-layer evasion, which is a Linux-specific attack pattern that would be missed by Windows-oriented detection logic
- Defense-in-depth is demonstrated by the fact that TA0005 (Defense Evasion) appears in two of the three rules — evasion combined with any other tactic is a reliable escalation signal
