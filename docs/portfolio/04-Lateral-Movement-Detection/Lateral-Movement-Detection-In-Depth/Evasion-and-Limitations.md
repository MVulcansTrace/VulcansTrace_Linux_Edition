# Lateral Movement Detection — Evasion and Limitations

## Known Limitations

| Limitation | Severity | Impact |
|---|---|---|
| Fixed time window | Medium | Slow lateral movement spreading over hours may evade detection |
| Admin-port-only scope | Medium | Attackers using non-standard ports or protocols are invisible |
| No protocol awareness | Low | Cannot distinguish valid SMB authentication from SMB-based exploitation |
| Single-technique detection | Low | Misses lateral movement via WMI over HTTP (ports 5985/5986). Cannot identify the specific tool or technique (e.g., PsExec, named pipes) — detects the connection pattern but not the method |
| No credential context | Medium | Cannot differentiate between authorized admin activity and compromised credentials |
| Source-IP-only grouping | Low | NAT or shared hosts may conflate multiple actors into one group |

---

## Slow Lateral Movement

Attackers who spread connections across a timeframe longer than `LateralWindowMinutes` (default 10) will evade the detector. A patient adversary connecting to one new host every 15 minutes would never trigger the threshold within a single window.

**Mitigation:** Increase `LateralWindowMinutes` in the analysis profile for environments where slow movement is a concern. Future versions could implement adaptive windows that scale with observed network baseline.

---

## Non-Admin-Port Pivoting

By default, the detector monitors only ports 445 (SMB), 3389 (RDP), and 22 (SSH). The `AdminPorts` list is configurable via the analysis profile, so the scope is limited only by the chosen configuration. Attackers who use alternative protocols — such as HTTP-based C2 tunnels, DNS pivoting, or custom TCP services on non-admin ports — bypass detection entirely.

**Mitigation:** Extend `AdminPorts` in the analysis profile to include environment-specific administrative ports. Future versions could support a "lateral heuristic" mode that monitors all internal-to-internal connections regardless of port.

---

## Encrypted Tunnel False Negatives

If an attacker establishes an encrypted tunnel (e.g., SSH port forwarding) through a compromised host, subsequent pivots through the tunnel appear as connections to a single destination IP — the tunnel endpoint. The detector sees one host rather than many.

**Mitigation:** Correlate with network flow data (NetFlow/sFlow) if available. The detector's design intentionally focuses on what iptables logs can reliably show.

---

## Credential Compromise Ambiguity

A finding does not distinguish between an attacker using stolen credentials and a legitimate administrator performing routine maintenance. Both produce identical iptables log entries.

**Mitigation:** Cross-reference findings with IAM logs, jump-server records, or change-management tickets. The detector provides the "when and where"; incident response provides the "who and why."

---

## DHCP and IP Reuse

In DHCP environments, IP addresses may be reassigned. A finding attributed to one host may actually represent multiple physical machines over time, or conversely, a single compromised laptop may receive different IPs during its attack.

**Mitigation:** Correlate findings with DHCP lease logs or MAC address data (available in the `LinuxSpecific` metadata of `UnifiedEvent` when parsing both iptables and nftables-format logs).

---

## Improvement Roadmap

| Priority | Improvement | Effort |
|---|---|---|
| High | Adaptive window sizing based on network baseline | Medium |
| High | Configurable port list via profile (already supported) | Done |
| Medium | Historical baseline comparison for per-host admin-connection norms | Medium |
| Medium | MAC-address-based grouping for DHCP environments | Low |
| Low | Integration with NetFlow for tunnel detection | High |
| Low | Machine learning model for anomalous admin-port behavior | High |

---

## Security Takeaways

- The detector is designed for the most common lateral movement techniques (SMB, RDP, SSH pivoting) and does not claim comprehensive coverage
- Slow, patient attackers and non-standard protocols are the primary evasion vectors — operators should layer additional detection capabilities
- Profile configuration is the first line of defense against evasion — tuning thresholds to the specific network environment is critical
- Correlation with other data sources (IAM, DHCP, NetFlow) significantly improves detection accuracy and reduces false positives
