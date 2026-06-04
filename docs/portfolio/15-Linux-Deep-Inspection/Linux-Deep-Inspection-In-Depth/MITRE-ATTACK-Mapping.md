# MITRE ATT&CK Mapping: Linux Deep Inspection

## MITRE ATT&CK Technique Mapping

| Technique ID | Technique Name | Detector | How VulcansTrace Addresses It |
|---|---|---|---|
| T1046 | Network Service Discovery | Flag Anomaly | **Primary detection target.** FIN-without-SYN and XMAS scan patterns are stealth reconnaissance techniques used to enumerate open ports without completing TCP handshakes. The detector flags each anomalous packet at Medium severity. |
| T1046 | Network Service Discovery | Interface Hopping | **Multi-interface reconnaissance.** An attacker pivoting between network interfaces to probe services on different segments generates rapid interface switching patterns. The detector validates switching within the configured time window (`InterfaceHoppingWindowMinutes`, Low/High=10 min, Med=5 min) and emits Medium-severity findings. |
| T1595 | Active Scanning | Flag Anomaly | **Pre-attack detection.** FIN and XMAS scans are active scanning techniques used during external reconnaissance. The detector identifies the specific scan type (stealth FIN scan or XMAS scan) in the finding details. |
| T1595 | Active Scanning | Interface Hopping | **Segmentation reconnaissance.** Active probing of multiple network segments via different interfaces indicates systematic network mapping during the reconnaissance phase. |
| T1557 | Man-in-the-Middle | MAC Spoofing | **L2 integrity violation.** An attacker associating multiple MAC addresses with a single IP may be using rogue hardware or MAC manipulation tools to impersonate trusted devices. The detector flags this at High severity. |
| T1557.001 | Man-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay | MAC Spoofing | **L2 reconnaissance.** MAC spoofing often accompanies network poisoning as attackers attempt to bypass port security and gain network access for credential relay attacks. |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Kernel Module | **Posture assessment.** The detector identifies which defensive kernel modules are active (conntrack, rate limiting, Layer 7 filtering). The absence of expected modules may indicate defenses were impaired or were never configured. Findings are emitted at Info severity. |
| T1048 | Exfiltration Over Alternative Protocol | Packet Size | **Data exfiltration detection.** Unusually large packets (> 3000 bytes) may indicate data being exfiltrated over non-standard protocols. The detector flags individual large packets at Medium severity. |
| T1571 | Non-Standard Port | Packet Size | **Covert channel detection.** Highly consistent packet sizes (≥ `PacketSizeConsistencyPercent` identical) indicate structured communication on non-standard ports, characteristic of covert channels. The aggregate analysis detects this pattern at Medium severity. |

---

## Attack Lifecycle Context

```
                    ┌──────────────────────────────────────────────────────────┐
                    │               MITRE ATT&CK Attack Lifecycle               │
                    └──────────────────────────────────────────────────────────┘

  RECONNAISSANCE          INITIAL ACCESS         EXECUTION          EXFILTRATION
  ────────────────        ──────────────         ──────────         ───────────
  ┌─────────────┐        ┌─────────────┐        ┌──────────┐       ┌──────────┐
  │ T1595       │        │ T1190       │        │ T1059    │       │ T1048    │
  │ Active      │───────▶│ Exploit    │───────▶│ Command  │──────▶│ Exfil    │
  │ Scanning    │        │ Public-Face│        │ Line Int.│       │ Alt Proto│
  └──────┬──────┘        └─────────────┘        └──────────┘       └──────────┘
         │
         │  ┌─────────────┐
         │  │ T1046        │
         ├─▶│ Network Svc  │◀── Flag Anomaly + Interface Hopping detect here
         │  │ Discovery    │
         │  └─────────────┘
         │
         │  ┌─────────────┐
         │  │ T1200        │
         ├─▶│ Hardware     │◀── MAC Spoofing detects here
         │  │ Additions    │
         │  └─────────────┘
         │
         │  ┌─────────────┐
         │  │ T1562.001    │
         └─▶│ Impair       │◀── Kernel Module assesses here
            │ Defenses     │
            └─────────────┘

         ▼
  DEFENDER ACTION
  ────────────────
  ┌──────────────────────────────────────────────────────────────────┐
  │  VulcansTrace Linux Deep Inspection                              │
  │  • Flag Anomaly: detects stealth/XMAS scans (T1046, T1595)      │
  │  • MAC Spoofing: detects L2 integrity violations (T1200)        │
  │  • Kernel Module: assesses defensive posture (T1562.001)        │
  │  • Interface Hopping: detects segmentation bypass (T1046, T1595)│
  │  • Packet Size: detects exfiltration/covert channels (T1048)    │
  │  • RiskEscalator: promotes correlated findings to Critical      │
  └──────────────────────────────────────────────────────────────────┘
```

The five detectors operate across the full attack lifecycle — from reconnaissance (flag anomalies, interface hopping) through defensive posture assessment (kernel modules) to exfiltration (packet sizes). The `RiskEscalator` correlates findings across phases, escalating independent Medium and High findings to Critical when they converge on the same host. All findings now carry explicit MITRE ATT&CK technique mappings, and the evidence bundle includes a `mitre-navigator-layer.json` that combines mapped detector/rule coverage with observed finding density for direct import into the MITRE ATT&CK Navigator.

---

## Correlation Matrix

| | Flag Anomaly | MAC Spoofing | Kernel Module | Interface Hopping | Packet Size | Port Scan (baseline) |
|---|---|---|---|---|---|---|
| **Flag Anomaly** | — | | | | | **→ Critical** |
| **MAC Spoofing** | | — | | **→ Critical** | | |
| **Kernel Module** | | | — | | | |
| **Interface Hopping** | | **→ Critical** | | — | | |
| **Packet Size** | | | | | — | |
| **Port Scan** | **→ Critical** | | | | | — |

The `RiskEscalator` defines two Linux-specific correlation rules:

1. **FlagAnomaly + PortScan → Critical** — Stealth scanning combined with broad port enumeration indicates advanced reconnaissance
2. **MacSpoofing + InterfaceHopping → Critical** — L2 identity manipulation combined with L3 segment pivoting indicates a coordinated multi-vector attack

---

## Detection Gaps and Confidence Notes

| Gap | Detector | Description | Confidence Impact |
|---|---|---|---|
| Slow scans | Flag Anomaly | FIN scans spread over hours generate few events per time window | Medium confidence for slow scans |
| VM migration | MAC Spoofing | Legitimate MAC changes during live migration trigger false positives | Medium confidence in virtualized environments |
| Missing signatures | Kernel Module | Modules not in the keyword set are not detected | Confidence varies by log format |
| Slow interface switching | Interface Hopping | Switching > 5 minutes apart evades the rapid-switch check | Low confidence for patient attackers |
| Boundary packets | Packet Size | Packets just above/below thresholds evade per-packet checks | Medium confidence for threshold-adjacent attacks |
| Cross-source dilution | Packet Size | Aggregate stats mix all sources, diluting per-attacker signals | Medium confidence in multi-source environments |

### Confidence Assessment

The subsystem provides **high confidence** for active, fast attacks — FIN scans, XMAS scans, rapid interface pivoting, ARP poisoning with MAC cycling, and large-packet exfiltration. These are the most common and immediately dangerous patterns observed in real-world Linux firewall logs.

Confidence decreases for slow, patient, or threshold-aware attackers who adapt their behavior to stay below detection thresholds. The `RiskEscalator` mitigates this by correlating independent weak signals — even if each individual finding is Low or Medium severity, their combination on the same host triggers Critical escalation.

---

## Security Takeaways

1. The subsystem directly addresses eight MITRE ATT&CK techniques across the reconnaissance, credential access, defense evasion, and exfiltration phases
2. Detection at the reconnaissance stage (T1046, T1595) provides the earliest possible warning, giving defenders time to respond before exploitation
3. The `RiskEscalator` correlation with baseline detectors (FlagAnomaly+PortScan, MacSpoofing+InterfaceHopping) provides higher-confidence alerts for advanced multi-signal attacks
4. The KernelModuleDetector addresses T1562.001 from a defensive perspective — identifying which capabilities exist rather than detecting their impairment directly
5. All findings carry explicit MITRE technique mappings, and evidence bundles include a Navigator-compatible layer JSON for direct import into the MITRE ATT&CK Navigator
6. Known gaps around slow and threshold-aware attacks are documented and addressed in the improvement roadmap with prioritization
7. The correlation matrix shows that the highest-severity findings come from cross-detector correlation, not from individual detectors — reinforcing the defense-in-depth design principle
