# Lateral Movement Detection — Attack Scenario

## Security Problem

An attacker has compromised a developer workstation (10.0.1.50) via a phishing payload. After establishing a foothold, they begin pivoting through the internal network, scanning for and connecting to internal servers via SMB (port 445) and SSH (port 22) to find high-value targets.

---

## Worked Example

### Synthetic iptables Log Data

```
Jan 15 09:01:12 kernel: [iptables] IN=eth0 OUT= SRC=10.0.1.50 DST=10.0.2.10 PROTO=TCP SPT=52341 DPT=445
Jan 15 09:02:34 kernel: [iptables] IN=eth0 OUT= SRC=10.0.1.50 DST=10.0.2.11 PROTO=TCP SPT=52342 DPT=445
Jan 15 09:03:01 kernel: [iptables] IN=eth0 OUT= SRC=10.0.1.50 DST=10.0.2.12 PROTO=TCP SPT=52343 DPT=445
Jan 15 09:04:45 kernel: [iptables] IN=eth0 OUT= SRC=10.0.1.50 DST=10.0.3.20 PROTO=TCP SPT=52344 DPT=22
Jan 15 09:06:12 kernel: [iptables] IN=eth0 OUT= SRC=10.0.1.50 DST=10.0.3.21 PROTO=TCP SPT=52345 DPT=22
```

Five connections from the same source IP to five distinct internal hosts on admin ports, all within 5 minutes.

---

## Detection Walkthrough

| Step | Operation | Result |
|---|---|---|
| Normalize | Parse iptables format, extract fields | 5 `UnifiedEvent` records |
| Filter | Internal source (10.0.1.50) AND internal dest AND admin port (445, 22) | All 5 events pass |
| Group | Group by SourceIP = 10.0.1.50 | Single group with 5 events |
| Sort | Order by timestamp | Events in chronological order |
| Window T=0 | end=0, start=0, window=[event 0], hosts={10.0.2.10} | Count=1, below threshold |
| Window T=1 | end=1, start=0, window=[events 0-1], hosts={10.0.2.10, 10.0.2.11} | Count=2, below threshold |
| Window T=2 | end=2, start=0, window=[events 0-2], hosts={10.0.2.10, .11, .12} | Count=3, meets High threshold |
| Detect | distinctHosts (3) >= LateralMinHosts (3 for High profile) | Finding created; inFinding = true |
| Window T=3 | end=3, start=0, window=[events 0-3], hosts={10.0.2.10, .11, .12, 10.0.3.20} | Count=4, finding extended |
| Window T=4 | end=4, start=0, window=[events 0-4], hosts={10.0.2.10, .11, .12, 10.0.3.20, .21} | Count=5, finding extended |
| Loop end | inFinding = true | Finding finalized with TimeRangeEnd = last event |

---

## The Finding

```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "category": "LateralMovement",
  "severity": "High",
  "sourceHost": "10.0.1.50",
  "target": "multiple internal hosts",
  "timeRangeStart": "2026-01-15T09:01:12",
  "timeRangeEnd": "2026-01-15T09:06:12",
  "shortDescription": "Lateral movement from 10.0.1.50",
  "details": "Contacted 5 internal hosts on admin ports."
}
```

Note: The finding spans the full burst from events 0 through 4 because all five connections fall within the 10-minute sliding window. The detector creates the finding when the threshold is first crossed at event 2, then extends it as events 3 and 4 add more distinct hosts. At loop end, the finding is finalized with the last event's timestamp and the peak distinct-host count.

> **Note:** The JSON below shows the finding object in isolation. In the actual evidence bundle, findings are wrapped in a larger JSON structure that includes metadata, parse errors, and warnings.

---

## Design Rationale

The detector fires at event 2 (the third distinct host) because the High profile threshold is 3 hosts in 10 minutes. At this point the attacker has connected to three different internal machines on SMB — a pattern extremely unlikely in normal operations. Because all five events fall within the same 10-minute window, the finding is extended to cover the full burst, capturing 5 distinct hosts in total.

---

## Security Value

| Aspect | Value |
|---|---|
| Detection speed | Alert fires within 2 minutes of the first lateral connection |
| Kill chain position | Catches the attacker between Initial Access and Exfiltration |
| Actionability | Source IP and host count provide immediate triage context |
| False positive risk | Low — 3 internal hosts on admin ports in 10 minutes is rare for legitimate traffic |
| Forensic value | Time range enables analysts to pull detailed logs for the attack window |

---

## Security Takeaways

- The sliding window catches the exact moment the attacker's behavior crosses from "possible admin" to "likely lateral movement"
- Admin-port filtering eliminates the noise that would make this pattern invisible in raw connection data
- One finding per contiguous burst gives analysts a clear starting point for investigation; separate time-separated bursts produce separate findings
- Profile thresholds allow tuning: the High profile catches this at 3 hosts, Medium at 4, and Low at 6 — custom profiles can set any value for specific network needs
