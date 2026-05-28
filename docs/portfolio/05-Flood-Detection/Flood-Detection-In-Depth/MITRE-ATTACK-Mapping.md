# Flood Detection — MITRE ATT&CK Mapping

## Technique Mapping

| MITRE Technique | ID | Tactic | How Detected | Coverage |
|---|---|---|---|---|
| Network Denial of Service: Direct Network Flood | T1498.001 | Impact (TA0040) | High-volume single-source connection floods | Direct |
| Network Denial of Service: Reflection Amplification | T1498.002 | Impact (TA0040) | Indirect — reflected traffic appears as high-volume source | Partial |
| Endpoint Denial of Service: OS Exhaustion Flood | T1499.001 | Impact (TA0040) | Indirect — connection table exhaustion via volume | Partial |
| Endpoint Denial of Service: Application Exhaustion Flood | T1499.003 | Impact (TA0040) | Indirect — application resource exhaustion via volume | Partial |
| Impact (Parent Tactic) | TA0040 | — | Volumetric DoS sub-techniques only | Narrow |

---

## Attack Lifecycle

```
 Reconnaissance        Initial Access          ┌── Execution ──┐
┌──────────────┐   ┌────────────────────┐      │                │
│ T1595 Active │   │ T1190 Exploit      │      │   Payload      │
│  Scanning    │──>│  Public-Facing App │─────>│   Delivery     │
└──────────────┘   └────────────────────┘      │                │
                                               └───────┬────────┘
                                                       │
                                                       v
                                          ┌────────────────────────┐
                                          │   IMPACT               │  <== DETECTED HERE
                                          │   T1498 Network DoS    │
                                          │   T1499 Endpoint DoS   │
                                          └────────────────────────┘
```

Flood attacks are typically the **final phase** in the kill chain — the attacker's goal is immediate disruption rather than follow-on exploitation. However, floods may also be used as a **diversion** to distract defenders while a separate intrusion proceeds.

---

## Detection Gaps

| Gap | Description | Risk Level |
|---|---|---|
| T1498.001 Distributed variant | Many sources each below threshold | High |
| T1499.002 Service Exhaustion Flood | Low-and-slow resource exhaustion | Medium |
| T1499.004 Application or System Exploitation | Crashing services via malformed packets | High |
| T1498.002 Reflection/Amplification | Spoofed source addresses mask real attacker | Medium |

---

## Security Takeaways

- The detector directly covers direct network floods (T1498.001) — a common volumetric DoS technique
- Reflection amplification (T1498.002) is partially covered because reflected traffic appears as high-volume from the reflector IP
- Endpoint exhaustion attacks (T1499) are indirectly detected when they manifest as high connection volumes
- The primary gap is distributed attacks — defending against DDoS requires infrastructure beyond what host-based log analysis can provide
