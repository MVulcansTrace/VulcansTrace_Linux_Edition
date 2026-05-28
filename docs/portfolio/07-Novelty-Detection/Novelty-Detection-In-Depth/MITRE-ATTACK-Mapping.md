# Novelty Detection — MITRE ATT&CK Mapping

## Technique Mapping

| MITRE Technique | ID | Tactic | How Detected | Coverage |
|---|---|---|---|---|
| Network Service Discovery | T1046 | Discovery (TA0007) | Single connections to services on unusual ports | Direct |
| Remote System Discovery | T1018 | Discovery (TA0007) | Single connections to previously unseen external hosts | Direct |
| Active Scanning | T1595 | Reconnaissance (TA0043) | Indirect — single probes may be part of broader scanning | Partial |
| Discovery (Parent Tactic) | TA0007 | — | All one-time reconnaissance and discovery patterns | Broad |

---

## Attack Lifecycle

```
 Reconnaissance           Initial Access         Execution
 ┌──────────────┐      ┌──────────────┐      ┌──────────────┐
 │ T1595 Active │      │ T1190 Exploit│      │ T1059 Script │
 │  Scanning    │──*──>│  Public-Face │─────>│  Interpreter │
 └──────┬───────┘      └──────────────┘      └──────┬───────┘
        │                                           │
        v                                           v
 ┌──────────────────────┐               ┌──────────────────────┐
 │   DISCOVERY          │  <== DETECTED │   Persistence        │
 │   T1046 Network Svc  │      HERE     │   T1053 Sched Task   │
 │   T1018 Remote Sys   │               └──────────────────────┘
 └──────────────────────┘
```

Novelty detection operates at the **discovery phase** — after initial compromise, when the attacker is mapping the environment to identify targets for lateral movement and data collection. It also catches reconnaissance (pre-compromise single probes).

---

## Detection Gaps

| Gap | Description | Risk Level |
|---|---|---|
| T1018 Remote System Discovery: IP-based only | Cannot detect discovery via ARP, NetBIOS, or other non-IP protocols | Low |
| T1046 Network Service Discovery: Port-based only | Cannot detect service fingerprinting within a single connection | Medium |
| T1082 System Information Discovery | Host-based discovery produces no network events | High |
| T1083 File and Directory Discovery | Host-based enumeration produces no network events | High |
| T1040 Network Sniffing | Passive discovery produces no connection events | Medium |

---

## Security Takeaways

- The detector directly covers network-based discovery techniques (T1046, T1018) by flagging one-time connections to external services and hosts
- Host-based discovery techniques (T1082, T1083) are fundamentally outside the detector's network-log-based scope
- The primary value is catching the **first contact** — the moment an attacker or compromised host reaches out to a new external destination
- Layering with host-based detection (process monitoring, file access monitoring) is necessary for comprehensive MITRE Discovery coverage
