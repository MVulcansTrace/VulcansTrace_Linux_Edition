# Evasion and Limitations: Linux Deep Inspection

## Known Limitations

| Limitation | Detector | Impact | Severity |
|---|---|---|---|
| Flag fragmentation across packets | Flag Anomaly | Flags split across TCP segments may not be detected | Low |
| Legitimate MAC changes (VM migration) | MAC Spoofing | False positive during live migration | Medium |
| Obfuscated or non-standard module names | Kernel Module | Missed modules if keyword not in signature set | Medium |
| Slow interface switching (> 5 min) | Interface Hopping | Evades the rapid-switch check | Medium |
| Packets at threshold boundaries | Packet Size | Packets just below `PacketSizeLargeThreshold` or just above `PacketSizeSmallThreshold` evade per-packet checks | Low |
| Small sample statistical noise | Packet Size | Aggregate findings may be unreliable below ~50 packets | Low |
| No per-source packet size analysis | Packet Size | Aggregate stats mix all sources together | Medium |
| Cross-IPv4/IPv6 MAC correlation | MAC Spoofing | IPv4 and IPv6 from same host may use different MACs | Low |
| No baseline learning | All | Thresholds are static and do not adapt to network norms | Medium |

---

### Flag Fragmentation Across Packets

TCP flags are extracted from individual packets' `LinuxSpecific["Flags"]` value. If an attacker crafts packets where FIN and SYN appear in separate segments of the same connection, the per-packet flag check will not detect the anomaly. However, this is an uncommon evasion technique because most firewalls log per-packet flags, not connection-state flags.

**Mitigation options:** Add connection-level flag tracking that accumulates flags across all packets in a TCP stream before checking. This would require maintaining per-connection state, increasing memory usage.

---

### Legitimate MAC Changes (VM Migration)

Virtual machine live migration (e.g., VMware vMotion, KVM live migration) can cause a source IP to appear with different MAC addresses as the VM moves between physical hosts. The detector would flag this as MAC spoofing.

**Mitigation options:** Add a time-window filter that only flags MAC changes occurring within a short period (e.g., < 1 minute), or allow operators to configure a list of known VM host MAC prefixes. A future improvement could correlate with VM management system logs to automatically whitelist migration events.

---

### Obfuscated or Non-Standard Module Names

The kernel module detector uses a fixed set of keyword signatures (`"conntrack"`, `"CT "`, `"limit"`, `"rate"`, etc.). Custom kernel modules, renamed modules, or non-standard logging formats may use different identifiers that are not in the signature set.

**Mitigation options:** Make the signature set configurable via `AnalysisProfile` or an external configuration file. Add support for regex-based signatures to handle naming variations.

---

### Slow Interface Switching

The interface hopping detector requires an interface change within the configured window (default 5 minutes, Low/High=10 minutes, Medium=5 minutes) to confirm rapid switching. An attacker who probes eth0 for longer than the window, then switches to eth1, evades the rapid-switch check even though the pivoting behavior is suspicious.

**Mitigation options:** The window is already configurable via `InterfaceHoppingWindowMinutes`. Add a cumulative multi-interface detection mode that flags any source using more than N interfaces over the entire analysis period, regardless of switching speed.

---

### Packets at Threshold Boundaries

The per-packet checks use profile-dependent thresholds: `PacketSizeLargeThreshold` (Low=4000, Med=3000, High=2000) for large, `PacketSizeSmallThreshold` (Low=20, Med=40, High=60) for small. An attacker sending 2900-byte packets or 42-byte packets evades both thresholds. The aggregate consistency check may catch sustained patterns, but a few boundary-evading packets will not trigger it.

**Mitigation options:** Make thresholds configurable per environment. Add adaptive thresholds based on the observed packet size distribution (e.g., flag packets in the 99th percentile).

---

### No Per-Source Packet Size Analysis

The aggregate statistical analysis (consistency and variance) operates on all packet sizes from all sources combined. An attacker's covert channel packets could be diluted by legitimate traffic from other sources. A per-source breakdown would provide cleaner signals.

**Mitigation options:** Group packet sizes by `SourceIP` before aggregate analysis, similar to how MAC Spoofing and Interface Hopping detectors group by source. This would increase memory usage proportionally to the number of unique sources.

---

## Improvement Roadmap

| Improvement | Description | Priority |
|---|---|---|
| Configurable interface hopping window | Extend `AnalysisProfile` to support sub-minute interface hopping windows | High |
| Per-source packet size analysis | Group packet sizes by SourceIP for aggregate statistical checks | High |
| VM migration whitelisting | Allow operators to configure known VM host MAC prefixes | Medium |
| Configurable kernel module signatures | Make the module keyword set extensible via configuration | Medium |
| Connection-level flag tracking | Accumulate flags across TCP stream packets before checking | Medium |
| Adaptive packet size thresholds | Use percentile-based thresholds from observed distribution | Low |
| Cumulative multi-interface detection | Flag sources using > N interfaces over the full analysis period regardless of switching speed | Low |
| Cross-detector signal enrichment | Include packet size statistics in flag anomaly findings and vice versa | Low |

---

## Security Takeaways

1. The five detectors are most effective against active, fast attacks — the most common and immediately dangerous patterns in Linux firewall logs
2. Slow, patient evasion techniques (gradual interface switching, threshold-boundary packets) require additional detection layers or configurable thresholds
3. VM migration false positives in MAC spoofing detection are a known, accepted trade-off — the detector prioritizes catching ARP poisoning over avoiding migration alerts
4. The fixed keyword set in KernelModuleDetector is a deliberate simplification — the detector provides quick posture assessment, not comprehensive module enumeration
5. Per-source packet size analysis is the highest-priority improvement because it would eliminate cross-source dilution in aggregate statistics
6. All limitations are documented and addressed in the improvement roadmap with prioritization based on real-world impact
