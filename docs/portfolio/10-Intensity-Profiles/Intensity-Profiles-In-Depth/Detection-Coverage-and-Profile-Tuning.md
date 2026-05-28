# Intensity Profiles — Detection Coverage and Profile Tuning

## Capability Mapping

| Capability | Detection Function | Relevant Framework |
|---|---|---|
| Port scan detection | Identify hosts probing multiple ports in a time window | MITRE T1046 (Network Service Discovery) |
| Flood / DoS detection | Detect high-volume event bursts from a single source | MITRE T1498 (Network DoS) |
| Lateral movement detection | Identify hosts contacting many internal destinations | MITRE T1021 (Remote Services) |
| Beaconing detection | Detect regular-interval communication to external hosts | MITRE T1071 (Application Layer Protocol) |
| Policy violation detection | Flag connections to disallowed ports and admin services | CIS Control 9 (Email and Web Browser Protections) |
| Novelty detection | Identify external destinations seen exactly once | MITRE T1018 (Remote System Discovery) |
| TCP flag anomaly detection | Detect abnormal TCP flag combinations | MITRE T1046 (Network Service Discovery) |
| MAC spoofing detection | Identify duplicate MAC addresses from different IPs | MITRE T1557 (Adversary-in-the-Middle) |
| Kernel module detection | Detect kernel-level packet anomalies | MITRE T1547 (Boot or Logon Autostart Execution) |
| Interface hopping detection | Identify traffic crossing unexpected interfaces | MITRE T1090 (Proxy) |
| Unusual packet size detection | Flag packets with abnormal payload sizes | MITRE T1071 (Application Layer Protocol) |
| C2 channel detection | Identify periodic command-and-control communication | MITRE T1071.001 (Web Protocols) |
| Privilege escalation detection | Detect spikes in admin port access | MITRE T1078 (Valid Accounts) |
| Risk escalation | Correlate multiple findings into escalated severity | MITRE TA0003 (Persistence) / TA0004 (Privilege Escalation) |
| Severity filtering | Gate output by minimum severity threshold | NIST SP 800-137 (Information Security Continuous Monitoring) |
| Profile-based tuning | Adjust all thresholds as a coherent unit | NIST SP 800-53 (Security and Privacy Controls) |

---

## Detector Coverage by Profile

```
  ┌──────────────────────────────────────────────────────────────┐
  │                    ALL PROFILES (shared)                     │
  │  ┌─────────┐ ┌───────┐ ┌──────────┐ ┌──────────┐ ┌───────┐ │
  │  │ PortScan│ │ Flood │ │ Lateral  │ │ Beaconing│ │Policy │ │
  │  └─────────┘ └───────┘ └──────────┘ └──────────┘ └───────┘ │
  │  ┌────────────┐ ┌─────────────┐                             │
  │  │ FlagAnomaly│ │ MACSpoofing │                             │
  │  └────────────┘ └─────────────┘                             │
  ├──────────────────────────────────────────────────────────────┤
  │              MEDIUM + HIGH ONLY                             │
  │  ┌─────────┐ ┌──────────────┐ ┌───────────────┐            │
  │  │ Novelty │ │ KernelModule │ │ InterfaceHop  │            │
  │  └─────────┘ └──────────────┘ └───────────────┘            │
  │  ┌─────────────────┐ ┌──────────┐ ┌───────────────┐        │
  │  │ UnusualPacketSz │ │    C2    │ │   PrivEsc     │        │
  │  └─────────────────┘ └──────────┘ └───────────────┘        │
  └──────────────────────────────────────────────────────────────┘
```

| Detector | Low | Medium | High |
|---|:---:|:---:|:---:|
| Port Scan | ON | ON | ON |
| Flood | ON | ON | ON |
| Lateral Movement | ON | ON | ON |
| Beaconing | ON | ON | ON |
| Policy Violation | ON | ON | ON |
| TCP Flag Anomaly | ON | ON | ON |
| MAC Spoofing | ON | ON | ON |
| Novelty | off | ON | ON |
| Kernel Module | off | ON | ON |
| Interface Hopping | off | ON | ON |
| Unusual Packet Size | off | ON | ON |
| C2 Channel | off | ON | ON |
| Privilege Escalation | off | ON | ON |

**Active detectors:** Low = 7, Medium = 13, High = 13

---

## Threshold Comparison Across Profiles

### Reconnaissance Thresholds

| Parameter | Low | Medium | High | Progression |
|---|---|---|---|---|
| PortScanMinPorts | 30 | 15 | 8 | ~2x per tier |
| PortScanWindowMinutes | 5 | 5 | 5 | Shared |
| FloodMinEvents | 400 | 200 | 100 | 2x per tier |
| FloodWindowSeconds | 60 | 60 | 60 | Shared |

### Lateral Movement Thresholds

| Parameter | Low | Medium | High | Progression |
|---|---|---|---|---|
| LateralMinHosts | 6 | 4 | 3 | ~1.5x per tier |
| LateralWindowMinutes | 10 | 10 | 10 | Shared |

### Beaconing Thresholds

| Parameter | Low | Medium | High | Progression |
|---|---|---|---|---|
| BeaconMinEvents | 8 | 6 | 4 | ~1.5x per tier |
| BeaconStdDevThreshold | 3.0 | 5.0 | 8.0 | Inverse — more jitter tolerated |
| BeaconMinIntervalSeconds | 60 | 30 | 10 | 2-3x per tier |

### C2 Channel Thresholds

| Parameter | Low | Medium | High | Progression |
|---|---|---|---|---|
| C2ToleranceSeconds | 10.0 | 5.0 | 8.0 | Tightens 2x Low→Medium, then loosens at High |
| C2MinIntervalSeconds | 120 | 60 | 30 | 2x per tier |
| C2MaxIntervalSeconds | 3600 | 1800 | 1800 | Halves Low→Medium, then holds at High |
| C2MinOccurrences | 5 | 3 | 2 | ~1.5x per tier |
| C2MinPatternEvents | 10 | 6 | 4 | ~1.7x per tier |
| C2MinGroupSize | 4 | 3 | 3 | Low requires one extra event before C2 analysis |

### Privilege Escalation Thresholds

| Parameter | Low | Medium | High | Progression |
|---|---|---|---|---|
| PrivilegeSpikeWindowMinutes | 10 | 5 | 10 | Tightens 2x Low→Medium, then loosens at High |

### Output Filter

| Parameter | Low | Medium | High |
|---|---|---|---|
| MinSeverityToShow | High | Medium | Info |
| MaxFindingsPerDetector | 100 | 100 | 100 |

### Policy Lists (All Profiles)

| List | Ports |
|---|---|
| AdminPorts | 445 (SMB), 3389 (RDP), 22 (SSH) |
| DisallowedOutboundPorts | 21 (FTP), 23 (Telnet), 445 (SMB) |

---

## Defense-in-Depth Diagram

```
  ┌─────────────────────────────────────────────────────────────────┐
  │                      INTENSITY PROFILES                        │
  │                    (Single Control Point)                       │
  └───────────────────────────┬─────────────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              v               v               v
     ┌────────────┐  ┌────────────┐  ┌────────────┐
     │    LOW     │  │   MEDIUM   │  │    HIGH    │
     │ Thresholds │  │ Thresholds │  │ Thresholds │
     │ 7 detectors│  │13 detectors│  │13 detectors│
     │ Show: High │  │Show: Medium│  │ Show: Info │
     └──────┬─────┘  └──────┬─────┘  └──────┬─────┘
            │               │               │
            v               v               v
  ┌──────────────────────────────────────────────────────────────┐
  │                     DETECTION LAYERS                         │
  │                                                              │
  │  Layer 1: Baseline        Layer 2: Linux       Layer 3: Adv  │
  │  ┌──────────────────┐     ┌─────────────────┐  ┌──────────┐ │
  │  │ PortScan         │     │ FlagAnomaly     │  │ C2       │ │
  │  │ Flood            │     │ MacSpoofing     │  │ PrivEsc  │ │
  │  │ Lateral          │     │ KernelModule    │  └──────────┘ │
  │  │ Beaconing        │     │ InterfaceHop    │               │
  │  │ PolicyViolation  │     │ UnusualPktSize  │               │
  │  │ Novelty          │     └─────────────────┘               │
  │  └──────────────────┘                                       │
  └──────────────────────┬───────────────────────────────────────┘
                         │
                         v
  ┌──────────────────────────────────────────────────────────────┐
  │  Risk Escalation Engine                                      │
  │  (Cross-correlates findings, escalates severity)             │
  └──────────────────────┬───────────────────────────────────────┘
                         │
                         v
  ┌──────────────────────────────────────────────────────────────┐
  │  MinSeverityToShow Filter                                    │
  │  (Gates output by profile-configured threshold)              │
  └──────────────────────┬───────────────────────────────────────┘
                         │
                         v
  ┌──────────────────────────────────────────────────────────────┐
  │  MaxFindingsPerDetector Cap                                  │
  │  (Caps visible findings per category)                        │
  └──────────────────────┬───────────────────────────────────────┘
                         │
                         v
                  Filtered + capped findings
```

---

## Tuning Recommendations

### When to Use Low Profile

- High-traffic production networks (>10,000 events/minute)
- Initial triage of unknown log data
- Monitoring dashboards where false positives are costly
- Compliance reporting that requires only confirmed high-severity findings

### When to Use Medium Profile

- General-purpose security analysis
- Investigation of suspicious activity flagged by SIEM alerts
- Networks with moderate traffic volumes
- Analysis requiring C2 and beaconing detection alongside baseline detectors

### When to Use High Profile

- Deep forensic investigation of known compromises
- Low-traffic networks where every connection matters
- Incident response scenarios requiring maximum visibility
- Analyst review of findings at all severity levels

### When to Use Custom Override Profile

- Investigating a specific APT with known beaconing intervals
- High-traffic servers that overwhelm standard flood thresholds
- Tuning for network-specific baselines (e.g., NAT gateways with inherently high connection counts)
- Testing and validating new threshold values before incorporating into presets

### Tuning Anti-Patterns

| Anti-Pattern | Risk | Recommendation |
|---|---|---|
| Always using High profile | Alert fatigue, analyst burnout | Start with Low, escalate to Medium or High based on findings |
| Setting all thresholds to minimum | All traffic flagged, no useful signal | Tune one detector at a time, measure false positive rate |
| Ignoring MinSeverityToShow | Missing findings that were computed but filtered | Review all findings at Info severity periodically to validate filter level |
| Modifying shared policy lists per profile | Inconsistent policy enforcement | Keep AdminPorts and DisallowedOutboundPorts consistent across all analysis |

---

## Security Takeaways

- The profile system implements defense-in-depth through progressive detector activation: Low provides baseline coverage, Medium adds deep inspection, High enables everything
- BeaconStdDevThreshold increases (3.0 → 5.0 → 8.0) from Low to High — the inverse of other thresholds — because higher sensitivity requires tolerating more natural jitter in timing patterns
- MinSeverityToShow runs after detection, escalation, and Beaconing/C2 deduplication, then MaxFindingsPerDetector caps the visible findings per category
- The six detectors that activate at Medium and High (Novelty, KernelModule, InterfaceHopping, UnusualPacketSize, C2, PrivilegeEscalation) represent the advanced threat surface — the attacks that baseline detectors are not designed to catch
- Tuning recommendations should be treated as starting points; every network has unique traffic patterns that may require custom overrides for optimal coverage
