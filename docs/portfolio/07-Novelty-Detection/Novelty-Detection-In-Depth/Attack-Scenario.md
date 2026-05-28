# Novelty Detection — Attack Scenario

## Security Problem

An attacker performs a reconnaissance probe against an external service to test connectivity before launching a broader operation. The probe consists of a single connection to a target that has never been seen before and is never contacted again — making it invisible to volume-based detectors.

---

## Worked Example

### Synthetic iptables Log Data

```
Jan 30 22:15:01 kernel: [iptables] IN=eth0 OUT=eth1 SRC=10.0.1.100 DST=93.184.216.34 PROTO=TCP SPT=49152 DPT=4444
Jan 30 22:15:02 kernel: [iptables] IN=eth0 OUT=eth1 SRC=10.0.1.100 DST=172.217.3.110 PROTO=TCP SPT=49153 DPT=443
Jan 30 22:15:03 kernel: [iptables] IN=eth0 OUT=eth1 SRC=10.0.1.100 DST=172.217.3.110 PROTO=TCP SPT=49154 DPT=443
Jan 30 22:15:04 kernel: [iptables] IN=eth0 OUT=eth1 SRC=10.0.1.100 DST=172.217.3.110 PROTO=TCP SPT=49155 DPT=443
```

Four events from the same source (10.0.1.100). Three go to 172.217.3.110:443 (a common CDN — likely legitimate browsing). One goes to 93.184.216.34:4444 — an unusual port on an unfamiliar IP, seen only once.

---

## Detection Walkthrough

| Step | Operation | Result |
|---|---|---|
| Normalize | Parse iptables format, extract fields | 4 `UnifiedEvent` records |
| Guard | `EnableNovelty` is true (Medium profile) | Continue |
| Filter | External destinations only | All 4 events pass (all external) |
| Pass 1: Build frequency | Group by (DestIP, DestPort) | `{(93.184.216.34, 4444): 1, (172.217.3.110, 443): 3}` |
| Pass 2: Event 1 | Key = (93.184.216.34, 4444), count = 1 | Singleton — finding emitted |
| Pass 2: Event 2 | Key = (172.217.3.110, 443), count = 3 | Not singleton — skip |
| Pass 2: Event 3 | Key = (172.217.3.110, 443), count = 3 | Not singleton — skip |
| Pass 2: Event 4 | Key = (172.217.3.110, 443), count = 3 | Not singleton — skip |

Only the first event is flagged. The three CDN connections are correctly excluded because 172.217.3.110:443 appears three times.

---

## The Finding

```json
{
  "Category": "Novelty",
  "Severity": "Low",
  "SourceHost": "10.0.1.100",
  "Target": "93.184.216.34:4444",
  "TimeRangeStart": "2026-01-30T22:15:01",
  "TimeRangeEnd": "2026-01-30T22:15:01",
  "ShortDescription": "1 novel destination(s) from 10.0.1.100",
  "Details": "Source 10.0.1.100 contacted 1 external destination(s) exactly once. This may indicate reconnaissance or testing of exfiltration channels."
}
```

The finding highlights the unusual destination: port 4444 is commonly associated with Metasploit's default reverse shell payload. While the severity is Low (this is only one connection), the context provides a valuable lead for investigation.

---

## Design Rationale

The detector flags this connection at Low severity because it represents a single data point. However, port 4444 on an external IP is suspicious enough to warrant investigation. The finding provides:

- **The source** (10.0.1.100) — which internal host made the connection
- **The destination** (93.184.216.34:4444) — the external endpoint, including the suspicious port
- **The time** (22:15:01) — enabling correlation with other logs

An analyst reviewing this finding might cross-reference with endpoint detection data, check if 93.184.216.34 appears on threat intelligence feeds, or examine the host 10.0.1.100 for signs of compromise.

---

## Security Value

| Aspect | Value |
|---|---|
| Detection type | Singleton — invisible to volume-based detectors |
| Suspicion level | Low severity but high investigative value (port 4444) |
| Complementary coverage | Catches what flood, scan, and beaconing detectors miss |
| Forensic enablement | Provides a lead that can be escalated through additional investigation |
| Analyst context | Source IP, destination IP:port, and timestamp for cross-referencing |

---

## Security Takeaways

- The novelty detector catches the reconnaissance probe that volume-based detectors would never see
- Port 4444 on a one-time external connection is a strong lead, even at Low severity
- The composite (IP, Port) key correctly separates the suspicious singleton from the legitimate CDN traffic
- Low severity is appropriate — this is a lead, not a conclusion — but it's a lead that could prevent a full compromise
