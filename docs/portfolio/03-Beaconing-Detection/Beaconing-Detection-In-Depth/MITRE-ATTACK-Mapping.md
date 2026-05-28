# MITRE ATT&CK Mapping

---

## Technique Mapping

| Technique | ID | When It Applies |
|-----------|-----|-----------------|
| Application Layer Protocol: Web Protocols | T1071.001 | Analyst-applied mapping when the beaconing channel is understood as HTTP/HTTPS-based C2 |
| Encrypted Channel: Asymmetric Cryptography | T1573.002 | Analyst-applied mapping when surrounding evidence shows command-and-control using TLS or similar asymmetric encryption |
| Command and Control | TA0011 | Tactic-level mapping -- beaconing is the behavioral signature of the C2 phase in the attack lifecycle |

> **Note:** `BeaconingDetector` itself does not inspect application-layer protocol, encryption, or port semantics. It groups by `(SourceIP, DestinationIP, DestinationPort)` and scores timing regularity, so these ATT&CK mappings come from analyst context layered on top of the timing finding.

---

## Why Beaconing Maps to Command and Control

Beaconing is the behavioral signature of the **Command and Control (C2) phase** in the attack lifecycle. After initial compromise, the attacker needs a persistent channel to deliver commands and receive data. The regular timing pattern is a side effect of how most C2 frameworks implement polling:

- **Persistent access:** The malware calls home at fixed intervals to check for new commands
- **Command receipt:** The interval determines how quickly the attacker can issue instructions
- **Data exfiltration:** Many C2 channels use the same beacon for data delivery
- **Sleep and avoid detection:** The interval is a balance between responsiveness and stealth

---

## Attack Lifecycle Position

```text
Reconnaissance -> Initial Access -> Execution -> Persistence -> ... -> C2 -> Exfiltration / Lateral Movement
                                                                     ^ VulcansTrace detects here
```

**Defensive value of C2 detection:**

- Suggests a host may be compromised -- beaconing is a well-known C2 indicator, but legitimate applications can produce similar patterns and the detector assigns only Medium severity
- Identifies the destination IP and port for investigation, potential blocking, and threat intel
- Enables correlation with lateral movement for escalation
- Provides timing evidence for incident timeline reconstruction

---

## Detection Coverage

| Beacon Type | Covered | Why |
|-------------|---------|-----|
| Fixed-interval HTTP/HTTPS | **Yes, if the traffic appears as regular connections in the logs** | Low std dev triggers the detector on all profiles, but Low profile's severity gate filters out standalone Medium-severity findings unless they are escalated |
| TLS-encrypted C2 | **Yes, by timing** | Encrypted payload is not inspected; detection relies solely on interval regularity (T1573.002 mapping is analyst-applied) |
| Lightly randomized intervals | **Partial** | Outcome depends on the actual interval set, trimming, and profile thresholds |
| Heavily randomized intervals | **Often no** | Larger jitter is less likely to survive the std dev threshold, especially on stricter profiles |
| Domain flux | **No** | Rotating destinations split across tuples -- each group has fewer events than `BeaconMinEvents` |
| DNS tunneling | **No, as content analysis** | Connection timing may still be visible, but the detector has no DNS query content fields for tunnel-specific inspection |
| Domain fronting | **No** | Traffic to the same CDN IP blends with legitimate traffic; timing alone cannot distinguish C2 from normal usage |

---

## Security Takeaways

1. **ATT&CK provides a common reference model** -- mapping detections helps analysts align findings with standard terminology for SOCs
2. **C2 detection suggests likely compromise** -- unlike reconnaissance indicators, this implies the breach may have already happened, but legitimate applications can produce similar patterns
3. **Coverage is partial by design** -- timing analysis catches protocol-agnostic patterns but misses content-level evasion
4. **Layered detection fills gaps** -- DPI, DNS analysis, and threat intel complement timing-based C2 detection
