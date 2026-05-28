# Evasion and Limitations: Port Scan Detection

## Known Limitations

| Limitation | Impact | Severity |
|---|---|---|
| Slow scanning across windows | An attacker spreading a scan over many hours may never exceed the threshold in any single window | Medium |
| Distributed scanning | Multiple source IPs each scanning a few ports evade per-source grouping | High |
| Long-span spreading | Events spread beyond the configured sliding window reduce the active distinct-port count below threshold | Medium |
| No protocol differentiation | UDP, TCP, and ICMP scans are all counted equally toward the same threshold | Low |
| No payload inspection | The detector identifies the scan pattern but does not distinguish between SYN, CONNECT, or FIN scans based on payload | Medium |
| Decoy traffic injection | An attacker may flood extra connections to dilute the signal, but distinct destination-port counting is resistant when decoys repeat already-seen ports | Low |
| Source IP spoofing | Findings point to the source IP in the log, which may be spoofed | Medium |
| Threshold evasion | An attacker who stays below the configured `PortScanMinPorts` threshold avoids detection entirely | Medium |
| No baseline learning | Thresholds are static per profile and do not adapt to the network's normal traffic patterns | Low |
| Single detector scope | Port scan findings are evaluated independently per source — cross-source correlation is not currently supported; the `RiskEscalator` only correlates findings from the same source (e.g., PortScan + FlagAnomaly) | Low |
| Low-profile filtering | Port scan findings are emitted at Medium severity, but the Low intensity profile filters to High severity only — port scan results are silently invisible on the Low profile despite `EnablePortScan` being `true` | Medium |

---

### Slow Scanning (Timing-Based Evasion)

An attacker who sends one probe every 10 minutes will generate events spread across many 5-minute windows. With a Medium threshold of 15 distinct ports per window, the attacker would need to probe at least 15 different ports within a single 5-minute window to trigger the detector. A slow scan of 100 ports over 1,000 minutes would produce zero findings.

**Mitigation options:** Increase sensitivity by using the High profile, or add a cumulative distinct-port counter that triggers on a longer time horizon. The current design prioritizes burst detection over slow-and-low detection because aggressive scans are more common and more immediately dangerous.

---

### Distributed Scanning

If an attacker controls multiple source IPs and distributes a scan across them (e.g., 5 ports per source from 3 sources), no individual source will exceed a threshold of 15. The detector evaluates each source independently and has no cross-source correlation logic.

**Mitigation options:** Cross-source correlation could be added to the `RiskEscalator` by grouping findings from the same destination subnet within a time window. Threat intelligence feeds could also flag known scanning infrastructure. These are future improvements.

---

### Sliding-Window Threshold Evasion

The current sliding-window approach avoids fixed clock-boundary splitting, but it still only evaluates `PortScanWindowMinutes` worth of activity at a time. A scan that keeps every 5-minute span below the configured distinct-port threshold can evade detection.

**Mitigation options:** Add longer-horizon cumulative detection or adaptive baselines for sources that steadily accumulate new destination ports over hours.

---

### No Protocol Differentiation

The detector counts distinct destination ports regardless of protocol. A source sending TCP SYNs to 15 ports and a source sending UDP probes to 15 ports are treated identically. In practice, this is acceptable because both patterns indicate reconnaissance, but it means the finding does not distinguish between TCP service scanning and UDP service enumeration.

**Mitigation options:** Add a protocol filter or separate thresholds per protocol. This would increase configuration complexity and is deferred until a real-world use case demands it.

---

### Source IP Spoofing

Firewall logs record the source IP from the packet header, which can be spoofed for connectionless protocols (UDP, ICMP). For TCP, spoofing requires more effort (blind spoofing) but is possible in some network configurations.

**Mitigation options:** Correlate with MAC address data (available in the `LinuxSpecific` metadata on iptables logs) and with the `MacSpoofingDetector` output. Spoofed IPs typically show inconsistent MAC addresses across events.

---

## Improvement Roadmap

| Improvement | Description | Priority |
|---|---|---|
| Adaptive thresholds | Learn the baseline distinct-port count per source and flag statistical outliers rather than using fixed thresholds | Medium |
| Cross-source correlation | Detect distributed scans by identifying multiple sources scanning the same destination within a time window | Medium |
| Protocol-aware counting | Separate thresholds for TCP, UDP, and ICMP to reduce false positives from mixed-protocol traffic | Low |
| Long-horizon cumulative mode | Add optional cumulative detection for slow scans that stay below the sliding-window threshold | Low |
| Destination-aware scoring | Weight ports by service criticality (e.g., SSH, RDP, database ports) to prioritize high-value scans | High |
| Scan type classification | Use TCP flag information from `LinuxSpecific` metadata to classify scans as SYN, CONNECT, FIN, XMAS, or NULL | Medium |

---

## Security Takeaways

1. The detector is most effective against fast, aggressive scans — the most common and immediately dangerous pattern
2. Slow and distributed scans require additional detection layers or future improvements to the detector
3. The sliding window removes fixed-boundary splitting, but slow scans can still evade by staying below the threshold in every configured window
4. Protocol and payload agnosticism is a deliberate simplification — both TCP and UDP scans represent reconnaissance
5. Source IP spoofing can be partially mitigated by reviewing `MacSpoofingDetector` findings (multiple MACs for one IP) alongside port scan results — though the pipeline does not currently correlate these two finding types automatically
6. The improvement roadmap prioritizes destination-aware scoring and adaptive thresholds for the highest impact
