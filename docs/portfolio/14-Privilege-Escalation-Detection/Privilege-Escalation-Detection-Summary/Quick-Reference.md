# Quick Reference: Privilege Escalation Detection

## Algorithm Steps

1. **Guard** — If `EnablePrivilegeEscalationDetection` is false or the event list is empty, return immediately with no findings
2. **Build admin port set** — Merge baseline ports {22, 2222, 2200, 22022, 3389, 5900, 5432, 3306} with `profile.AdminPorts`
3. **Filter admin events** — Select events where `DestinationPort` is in the admin port set
4. **Group by source** — Group filtered events by `SourceIP`
5. **Order chronologically** — Sort each source group by `Timestamp`
6. **DetectAdminSpikes** — Two-pointer sliding window; flag windows with >= `PrivilegeSpikeMinAttempts` events (profile-dependent, default 5) (High severity)
7. **DetectAdminPortSweeps** — Two-pointer sliding window with dictionary port tracking; flag when >= `PrivilegeSweepMinDistinctPorts` distinct admin ports appear (profile-dependent, default 3) (Medium severity)

---

## Configuration Parameters

| Parameter | Type | Description | Low | Medium | High |
|---|---|---|---|---|---|
| `EnablePrivilegeEscalationDetection` | `bool` | Enable/disable privilege escalation detection | false | true | true |
| `PrivilegeSpikeWindowMinutes` | `int` | Time window size in minutes for spike and sweep detection | 10 | 5 | 10 |
| `PrivilegeSpikeMinAttempts` | `int` | Minimum events in window to trigger a spike finding | 8 | 5 | 4 |
| `PrivilegeSweepMinDistinctPorts` | `int` | Minimum distinct admin ports in window to trigger a sweep finding | 4 | 3 | 2 |
| `AdminPorts` | `IReadOnlyList<int>` | Additional admin ports to monitor (merged with baseline) | [445, 3389, 22] | [445, 3389, 22] | [445, 3389, 22] |

---

## Downstream Pipeline

```
┌─────────────┐    ┌──────────────────┐    ┌──────────────────────────┐    ┌────────────────┐
│  Log         │    │  UnifiedEvent     │    │  PrivilegeEscalation      │    │  Evidence       │
│  Normalizer  │───▶│  Stream           │───▶│  Detector                 │───▶│  Packaging      │
└─────────────┘    └──────────────────┘    └──────────────────────────┘    └────────────────┘
                                                     │
                                              ┌──────┴──────┐
                                              ▼             ▼
                                     ┌──────────────┐ ┌──────────────┐
                                     │  Finding:     │ │  Finding:     │
                                     │  Category=    │ │  Category=    │
                                     │  PrivEsc      │ │  PrivEsc      │
                                     │  Severity=    │ │  Severity=    │
                                     │  High (spike) │ │  Med (sweep)  │
                                     └──────────────┘ └──────────────┘
```

---

## Finding Structure

### Admin Spike Finding

| Field | Value |
|---|---|
| `Category` | `"PrivilegeEscalation"` |
| `Severity` | `High` |
| `SourceHost` | The attacking source IP |
| `Target` | `"admin ports in {windowMinutes}min window"` |
| `TimeRangeStart` | Earliest timestamp in the matching window |
| `TimeRangeEnd` | Latest timestamp in the matching window |
| `ShortDescription` | `"Potential privilege escalation indicator: {count} admin access attempts from {sourceIP}"` |
| `Details` | `"Detected {count} admin port access attempts within {windowMinutes} minutes, suggesting possible brute force or escalation activity."` |

### Admin Port Sweep Finding

| Field | Value |
|---|---|
| `Category` | `"PrivilegeEscalation"` |
| `Severity` | `Medium` |
| `SourceHost` | The attacking source IP |
| `Target` | `"ports {port1}, {port2}, {port3}..."` (up to 5 shown) |
| `TimeRangeStart` | Earliest timestamp in the matching window |
| `TimeRangeEnd` | Latest timestamp in the matching window |
| `ShortDescription` | `"Admin port sweep from {sourceIP}"` |
| `Details` | `"Detected access attempts across {distinctPortCount} admin ports within {windowMinutes} minutes."` |

---

## Baseline Admin Ports

| Port | Service | Relevance |
|---|---|---|
| 22 | SSH | Primary remote admin protocol on Linux |
| 2222 | SSH (alt) | Common alternate SSH port |
| 2200 | SSH (alt) | Another common alternate SSH port |
| 22022 | SSH (alt) | Non-standard SSH port used by some admins |
| 3389 | RDP | Remote Desktop Protocol — common lateral target |
| 5900 | VNC | Virtual Network Computing — remote desktop |
| 5432 | PostgreSQL | Database — often targeted for data access |
| 3306 | MySQL | Database — often targeted for data access |

---

## Complexity

| Dimension | Complexity | Notes |
|---|---|---|
| Time (spikes) | O(N) per source | Two-pointer sliding window, single pass |
| Time (sweeps) | O(N) per source | Two-pointer sliding window with dictionary tracking |
| Space | O(N) per source | Stores ordered event list per source group |
| Admin port lookup | O(1) | `IReadOnlyCollection.Contains` on small set |

---

## MITRE ATT&CK

| Technique ID | Name | Relevance |
|---|---|---|
| T1110 | Brute Force | Primary — admin spike detection flags rapid credential guessing |
| T1078 | Valid Accounts | Related — successful brute force yields valid credentials |
| T1548 | Abuse Elevation Control Mechanism | Related — attacker seeks admin access for elevation |
| TA0004 | Privilege Escalation | Tactic — the detector's primary goal |
| T1021 | Remote Services | Related — SSH, RDP, VNC are remote admin services |

---

## Evasion Summary

| Evasion Technique | Effect on Detection | Mitigation |
|---|---|---|
| Slow brute force (spread over hours) | Events fall outside the sliding window, count may not meet threshold | Reduce window size via High profile |
| Single-port low-rate attempts | Below spike threshold (`PrivilegeSpikeMinAttempts`) | Correlate with beaconing detector |
| Port sweep with few ports | Below sweep threshold (`PrivilegeSweepMinDistinctPorts`) | Lower threshold or add more admin ports |
| Use of non-standard admin ports | Not in baseline or profile admin port list | Extend `AdminPorts` in profile |
| Distributed attack (multiple source IPs) | Each source evaluated independently | Correlate with lateral movement detector |
| Legitimate admin activity | May trigger false positives | Disable in Low profile or tune window |

---

## File References

| File | Role |
|---|---|
| [PrivilegeEscalationDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/PrivilegeEscalationDetector.cs) | Detector implementation |
| [AnalysisProfile.cs](../../../../VulcansTrace.Linux.Engine/AnalysisProfile.cs) | Threshold configuration record |
| [AnalysisProfileProvider.cs](../../../../VulcansTrace.Linux.Engine/Configuration/AnalysisProfileProvider.cs) | Intensity-based presets |
| [PrivilegeEscalationDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/PrivilegeEscalationDetectorTests.cs) | Test suite |

---

## Security Takeaways

1. Dual detection modes (spikes + sweeps) cover both brute-force and service-enumeration attack strategies
2. The baseline admin port list targets the most commonly exploited Linux services without requiring configuration
3. Profile-based activation and window sizing let operators tune sensitivity to their environment
4. High severity for spikes reflects the immediate danger of successful brute-force credential attacks
5. The sweep detector resets state and continues scanning after each match, enabling detection of multiple separate sweeps from the same source
