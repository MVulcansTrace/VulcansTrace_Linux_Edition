# MITRE ATT&CK Mapping: Port Scan Detection

## MITRE ATT&CK Technique Mapping

| Technique ID | Technique Name | How VulcansTrace Addresses It |
|---|---|---|
| T1046 | Network Service Discovery | **Primary detection target.** The detector identifies source IPs probing multiple distinct destination ports within sliding time windows. A finding is emitted when the distinct-port count meets or exceeds a configurable threshold (8–30 depending on profile). |
| T1595 | Active Scanning | **Pre-attack detection.** External reconnaissance of the target network's exposed services generates iptables log entries that the detector analyzes. Findings identify the scanning source IP and time range. |
| T1595.001 | Active Scanning: Scanning IP Blocks | **Indirectly addressed.** The port scan detector is service/port oriented. A same-port sweep across many destination IPs does not satisfy `PortScanMinPorts` by itself; other signals such as flood, novelty, or future host-sweep detection are better fits. |
| T1595.002 | Active Scanning: Vulnerability Scanning | **Indirectly addressed.** Vulnerability scanners typically probe many ports per host, generating the same traffic pattern as a port scan. The detector flags the reconnaissance behavior even though it cannot distinguish vulnerability scanning from simple port scanning. |

---

## Attack Lifecycle Context

```
                    ┌──────────────────────────────────────────────────────────┐
                    │               MITRE ATT&CK Attack Lifecycle               │
                    └──────────────────────────────────────────────────────────┘

  RECONNAISSANCE          INITIAL ACCESS         EXECUTION          PERSISTENCE
  ────────────────        ──────────────         ──────────         ───────────
  ┌─────────────┐        ┌─────────────┐        ┌──────────┐       ┌──────────┐
  │ T1595       │        │ T1190       │        │ T1059    │       │ T1053    │
  │ Active      │───────▶│ Exploit    │───────▶│ Command  │──────▶│ Scheduled│
  │ Scanning    │        │ Public-Facing│        │ Line Int.│       │ Task      │
  └──────┬──────┘        └─────────────┘        └──────────┘       └──────────┘
         │
         │  ┌─────────────┐
         │  │ T1046        │
         └─▶│ Network Svc  │◀── VulcansTrace detects here
            │ Discovery    │
            └─────────────┘

         ▼
  DEFENDER ACTION
  ────────────────
  ┌──────────────────────────────────────────────────────────────────┐
  │  VulcansTrace Port Scan Detector                                │
  │  • Identifies scanning source IP                                │
  │  • Counts distinct destination ports per sliding time window     │
  │  • Emits Medium-severity finding (see note below)               │
  │  • RiskEscalator promotes to Critical if combined w/ FlagAnomaly│
  └──────────────────────────────────────────────────────────────────┘
```

The detector operates at the earliest detectable stage of the attack lifecycle — reconnaissance. Detecting port scans gives defenders a window of opportunity to harden services, block the scanning IP, or increase monitoring before the attacker moves to initial access.

> **Note on profile visibility:** On the Low intensity profile, `MinSeverityToShow` is set to `High`. Since port scan findings emit at Medium severity, standalone port scan findings are filtered from results on Low profile. Only findings escalated to Critical severity (through RiskEscalator correlation with FlagAnomaly) remain visible. Medium and High profiles show all port scan findings.

---

## Detection Gaps and Confidence Notes

| Gap | Description | Confidence Impact |
|---|---|---|
| Slow scans | Probes spread across many windows may not meet per-window threshold | Medium confidence for slow scans |
| Distributed scans | Multiple sources each scanning below threshold evade detection | Low confidence for distributed reconnaissance |
| Threshold tuning | Static thresholds may not match all network baselines | Confidence varies by environment |
| Protocol mixing | TCP and UDP events are counted together | No impact — both indicate reconnaissance |
| Spoofed sources | Finding attributes the scan to the logged source IP | Medium confidence for attribution |

### Confidence Assessment

The detector provides **high confidence** for fast, single-source port scans — the most common pattern observed in real-world iptables logs. Confidence decreases for slow, distributed, or spoofed scans, which require additional detection layers.

When the `RiskEscalator` detects that a source host has time-correlated port scan and flag anomaly findings, it escalates those participating findings to Critical severity — the combination of independent signals reduces the likelihood of a false positive.

---

## Security Takeaways

1. The detector directly addresses MITRE T1046 (Network Service Discovery) and T1595 (Active Scanning) — two of the most common pre-attack techniques
2. Detection at the reconnaissance stage provides the earliest possible warning, giving defenders time to respond before exploitation
3. The `RiskEscalator` correlation with flag anomaly findings (T1595 + T1046 + evasion) escalates the participating findings to Critical severity
4. Known gaps around slow and distributed scanning are documented and addressed in the improvement roadmap
5. Profile-based thresholds allow defenders to increase detection sensitivity during active incident response without code changes
6. The detector's findings provide source IP and time range context that maps directly to incident response workflows
