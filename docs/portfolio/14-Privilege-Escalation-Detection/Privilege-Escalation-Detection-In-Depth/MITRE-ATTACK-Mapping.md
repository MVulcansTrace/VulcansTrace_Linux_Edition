# MITRE ATT&CK Mapping: Privilege Escalation Detection

## MITRE ATT&CK Technique Mapping

| Technique ID | Technique Name | How VulcansTrace Addresses It |
|---|---|---|
| T1110 | Brute Force | **Primary detection target.** The `DetectAdminSpikes` sub-detector identifies rapid-fire admin-port access attempts (>= 5 per window) characteristic of credential brute-force attacks against SSH, databases, and remote desktop services. |
| T1078 | Valid Accounts | **Indirectly addressed.** Successful brute-force attacks (T1110) yield valid account credentials. While the detector cannot observe authentication outcomes, the spike pattern indicates an active attempt to obtain valid credentials. |
| T1548 | Abuse Elevation Control Mechanism | **Contextually relevant.** Attackers targeting admin services are attempting to gain elevated privileges. The detector identifies the network-level indicator of this activity — repeated access to administrative interfaces. |
| TA0004 | Privilege Escalation | **Tactic-level mapping.** The detector's entire purpose aligns with this tactic. Both sub-detectors identify behaviors that precede or constitute privilege escalation — brute-force credential attacks and admin service enumeration. |
| T1021 | Remote Services | **Directly observed.** The admin port set includes remote service ports (SSH 22, RDP 3389, VNC 5900). The sweep detector specifically flags attackers probing multiple remote services to find an entry point. |

---

## Sub-Technique Mapping

| Sub-Technique ID | Sub-Technique Name | Relevance |
|---|---|---|
| T1110.001 | Brute Force: Password Guessing | **High.** The spike detector catches rapid password guessing attempts against admin services. |
| T1110.003 | Brute Force: Password Spraying | **Medium.** If the attacker targets multiple admin ports with few attempts each, the sweep detector may catch the pattern. |
| T1021.004 | Remote Services: SSH | **High.** SSH (port 22) is in the baseline admin port set and is the most commonly targeted service. |
| T1021.001 | Remote Services: Remote Desktop Protocol | **High.** RDP (port 3389) is in the baseline admin port set. |
| T1078.001 | Valid Accounts: Default Accounts | **Indirect.** Brute-force attacks often target default accounts on admin services. |

---

## Attack Lifecycle Context

```
                    ┌──────────────────────────────────────────────────────────┐
                    │               MITRE ATT&CK Attack Lifecycle               │
                    └──────────────────────────────────────────────────────────┘

  INITIAL ACCESS           PRIVILEGE ESCALATION     PERSISTENCE         DEFENSE EVASION
  ────────────────         ──────────────────       ───────────         ────────────────
  ┌─────────────┐         ┌─────────────┐          ┌──────────┐        ┌──────────┐
  │ T1190       │         │ T1548       │          │ T1053    │        │ T1070    │
  │ Exploit     │────────▶│ Abuse Elev. │─────────▶│ Scheduled│───────▶│ Indicator│
  │ Public-Facing│         │ Control Mech│          │ Task      │        │ Removal  │
  └──────┬──────┘         └─────────────┘          └──────────┘        └──────────┘
         │
         │    ┌─────────────┐         ┌──────────────┐
         │    │ T1110       │         │ T1078        │
         └───▶│ Brute Force │────────▶│ Valid        │◀── VulcansTrace detects here
              │             │         │ Accounts     │     (spike + sweep sub-detectors)
              └─────────────┘         └──────────────┘

              ┌─────────────┐
              │ T1021       │
              │ Remote      │◀── VulcansTrace detects here
              │ Services    │     (admin port sweep)
              └─────────────┘

         ▼
  DEFENDER ACTION
  ────────────────
  ┌──────────────────────────────────────────────────────────────────┐
  │  VulcansTrace Privilege Escalation Detector                     │
  │  • Detects brute-force bursts against admin services (High)     │
  │  • Detects multi-port admin service enumeration (Medium)        │
  │  • Identifies source IP, targeted ports, and time range         │
  │  • Adapts detection window via intensity profiles               │
  └──────────────────────────────────────────────────────────────────┘
```

The detector operates at the critical privilege escalation phase — the point where an attacker transitions from initial access to administrative control. Detecting brute-force and enumeration patterns at this stage gives defenders the opportunity to block the attacker before they establish persistence or begin defense evasion.

---

## Detection Gaps and Confidence Notes

| Gap | Description | Confidence Impact |
|---|---|---|
| Slow brute force | Probes spread across windows may not meet per-window threshold | Medium confidence for slow attacks |
| Distributed attacks | Multiple sources each below threshold evade per-source grouping | Low confidence for distributed campaigns |
| Authentication outcome | Cannot distinguish successful from failed logins | Finding indicates attempt, not compromise |
| Non-standard ports | Services on ports outside the admin set are invisible | Confidence limited to monitored ports |
| Legitimate admin traffic | Automated tools may trigger false positives | Higher false-positive rate in admin-heavy environments |

### Confidence Assessment

The detector provides **high confidence** for fast, single-source brute-force attacks and multi-port admin sweeps — the two most common privilege escalation patterns observed on Linux servers. Confidence decreases for slow, distributed, or non-standard-port attacks, which require additional detection layers.

The dual sub-detector approach increases overall confidence: an attacker who evades the spike detector (by limiting attempts per port) is more likely to trigger the sweep detector (by probing multiple admin services), and vice versa.

---

## Security Takeaways

1. The detector directly addresses MITRE T1110 (Brute Force) and T1021 (Remote Services) — the most common network-visible privilege escalation techniques
2. Detection at the privilege escalation stage provides a critical warning window — defenders can act before the attacker establishes persistence
3. The dual sub-detector design provides overlapping coverage, increasing the likelihood that at least one pattern will be detected
4. Known gaps around authentication outcomes and distributed attacks are documented and addressed in the improvement roadmap
5. Profile-based activation ensures the detector is used in contexts where it provides the highest confidence, avoiding noise in inappropriate environments
6. Findings provide source IP, targeted ports, and time range context that maps directly to incident response workflows for T1110 and T1021
