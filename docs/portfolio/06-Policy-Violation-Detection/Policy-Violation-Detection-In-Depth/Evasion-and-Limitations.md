# Policy Violation Detection — Evasion and Limitations

## Known Limitations

| Limitation | Severity | Impact |
|---|---|---|
| Port-based only | High | Protocol tunneling on allowed ports is invisible |
| No payload inspection | High | Cannot detect what data was actually transferred |
| No frequency analysis | Medium | Cannot distinguish one-time mistake from systematic abuse |
| No baseline awareness | Medium | Cannot flag unusual ports that aren't on the disallowed list |
| Fixed port list | Medium | New or non-standard ports must be manually added |
| No direction awareness for inbound | Low | Cannot detect inbound connections on disallowed ports |

---

## Protocol Tunneling on Allowed Ports

An attacker who encapsulates prohibited traffic within allowed protocols (e.g., SSH tunneling over port 443, DNS-based exfiltration) will not be detected. The detector operates at the transport layer and cannot see application-layer tunneling.

**Mitigation:** Deploy deep packet inspection (DPI) or network anomaly detection tools alongside this detector. The policy violation detector catches the easy cases; DPI catches the sophisticated ones.

---

## Allowed-Port Abuse

Attackers who use protocols on allowed ports (e.g., HTTPS on port 443) for exfiltration bypass the detector entirely. This is among the most common evasion techniques in practice — many modern C2 frameworks default to HTTPS.

**Mitigation:** Layer with beaconing detection (which identifies regular HTTPS connections to C2 infrastructure) and volume-based anomaly detection (which catches bulk exfiltration over any protocol).

---

## No Payload Visibility

The detector knows that an internal host connected to an external IP on port 21, but it cannot determine what data was transferred. A finding could represent an empty connection attempt or a multi-gigabyte data dump.

**Mitigation:** Correlate findings with network flow data (NetFlow/sFlow) for volume analysis, and with proxy logs for application-layer inspection.

---

## Static Port List

The disallowed port list is defined in the analysis profile and requires manual updates. If a new protocol becomes a threat (e.g., a vulnerability in a service on port 8443), it must be manually added to the profile.

**Mitigation:** Implement dynamic port list updates from a threat intelligence feed or SIEM policy management tool. For v1, the static list covers three historically risky protocols (FTP on port 21, Telnet on port 23, SMB on port 445) that transmit credentials or sensitive data in cleartext or are commonly exploited for lateral movement.

---

## No Anomaly Detection for Unusual Ports

The detector only fires on explicitly disallowed ports. An internal host connecting to an external IP on an unusual but not disallowed port (e.g., port 6667 for IRC-based C2) will not be flagged.

**Mitigation:** The novelty detector (folder 07) complements this by flagging first-time connections to external IP:port combinations, regardless of whether the port is on the disallowed list.

---

## Improvement Roadmap

| Priority | Improvement | Effort |
|---|---|---|
| High | Dynamic port list from threat intelligence feeds | Medium |
| High | Integration with DPI for tunnel detection | High |
| Medium | Frequency analysis per source (systematic vs. one-time) | Low |
| Medium | Destination reputation scoring | Medium |
| Low | Payload volume estimation via NetFlow correlation | Medium |
| Low | ML-based anomaly detection for unusual outbound ports | High |

---

## Security Takeaways

- The detector is highly effective against naive exfiltration on known-prohibited protocols but has significant blind spots for sophisticated evasion
- Protocol tunneling on allowed ports is the most impactful limitation — layering with DPI is recommended for high-security environments
- The static port list is adequate for v1 but should evolve toward dynamic threat-intelligence-driven configuration
- The novelty detector (folder 07) provides complementary coverage for connections to unusual but not explicitly prohibited external destinations
