# MITRE ATT&CK Mapping

---

## Technique Mapping

| Technique | ID | When It Applies |
|-----------|-----|-----------------|
| Application Layer Protocol | T1071 | Analyst-applied mapping when the C2 channel uses HTTP, HTTPS, DNS, or other application-layer protocols |
| Non-Application Layer Protocol | T1095 | Analyst-applied mapping when the C2 channel uses raw TCP, UDP, or other non-application-layer protocols |
| Encrypted Channel | T1573 | Analyst-applied mapping when surrounding evidence shows C2 using encrypted communication |
| Command and Control | TA0011 | Tactic-level mapping -- C2 channel patterns are the behavioral signature of the C2 phase in the attack lifecycle |

> **Note:** `C2ChannelDetector` itself does not inspect application-layer protocol, encryption, or port semantics. It groups by `{SourceIP}-{DestIP}:{DestPort}-{Protocol}` and scores interval clustering, so these ATT&CK mappings come from analyst context layered on top of the timing finding.

---

## Why C2 Channel Detection Maps to Command and Control

C2 channel detection targets the **Command and Control (C2) phase** in the attack lifecycle. After initial compromise, the attacker needs a persistent channel to deliver commands and receive data. The periodic timing pattern is a side effect of how most C2 frameworks implement polling:

- **Persistent access:** The malware calls home at regular intervals to check for new commands
- **Command receipt:** The interval determines how quickly the attacker can issue instructions
- **Data exfiltration:** Many C2 channels use the same connection pattern for data delivery
- **Ephemeral port rotation:** New source ports per connection help evade simplistic detection rules

---

## Attack Lifecycle Position

```text
Reconnaissance -> Initial Access -> Execution -> Persistence -> ... -> C2 -> Exfiltration / Lateral Movement
                                                                      ^ VulcansTrace detects here
```

**Defensive value of C2 channel detection:**

- Strongly suggests a host is compromised (not just "suspicious") -- periodic communication within a tolerance window is a high-fidelity C2 indicator, but legitimate applications can produce similar patterns
- Identifies the destination IP, port, and protocol for investigation, potential blocking, and threat intel
- Provides timing evidence with tolerance bounds for incident timeline reconstruction
- Complements the Beaconing detector for broader C2 coverage

---

## Detection Coverage

| C2 Type | Covered | Why |
|---------|---------|-----|
| Fixed-interval C2 over TCP | **Yes** | All deltas land in one bucket; triggers on Medium and High profiles |
| C2 with light jitter (within tolerance) | **Yes, on Medium** | Medium's 5s tolerance clusters lightly jittered intervals; High's 8s tolerance can group a wider spread |
| C2 with heavy jitter (beyond tolerance) | **Often no** | Deltas spread across multiple buckets; no single bucket reaches min occurrences |
| C2 over multiple intervals | **Partial** | Each interval creates its own bucket; each needs enough deltas independently |
| C2 with ephemeral port rotation | **Yes** | Source port excluded from grouping key; rotation does not dilute the pattern |
| Domain flux | **No** | Rotating destinations split events across groups; each group has fewer events |
| DNS tunneling | **No, as content analysis** | Connection timing may still be visible, but the detector has no DNS query content fields for tunnel-specific inspection |
| Domain fronting | **No** | Traffic to the same CDN IP blends with legitimate traffic; timing alone cannot distinguish C2 from normal usage |

---

## Complementary Coverage with Beaconing Detector

The C2 Channel detector and Beaconing detector provide overlapping but distinct C2 coverage:

| Aspect | Beaconing (Std Dev) | C2 Channel (Bucketization) |
|--------|--------------------|---------------------------|
| Statistical method | Population standard deviation | Tolerance-based clustering |
| What it measures | Overall interval regularity | Interval clustering |
| Catches | Metronome-like precision | Repeated similar intervals |
| Misses | Outlier-inflated channels | Heavily jittered channels |
| Source port handling | Excluded from grouping | Excluded from grouping |
| Severity | Medium (escalated to Critical with LateralMovement) | High |
| Low profile | Enabled | Disabled |

Together, the two detectors cover a broader range of C2 timing patterns than either could alone.

---

## Security Takeaways

1. **ATT&CK provides a common reference model** -- mapping detections helps analysts align findings with standard terminology for SOCs
2. **C2 detection suggests likely compromise** -- unlike reconnaissance indicators, this strongly implies the breach has already happened, but legitimate applications can produce similar patterns
3. **Coverage is partial by design** -- timing analysis catches protocol-agnostic patterns but misses content-level evasion
4. **Layered detection fills gaps** -- the Beaconing detector, DPI, DNS analysis, and threat intel complement C2 channel detection
5. **T1071, T1095, and T1573 are analyst-applied** -- the detector provides timing evidence; protocol and encryption context comes from surrounding analysis
