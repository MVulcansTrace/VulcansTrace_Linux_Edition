# Flood Detection — Attack Scenario

## Security Problem

An external attacker launches a TCP SYN flood against a public-facing web server, attempting to exhaust its connection table and deny service to legitimate users. The attack generates hundreds of SYN connection attempts per second from a single source IP.

---

## Worked Example

### Synthetic iptables Log Data

```
Jan 20 14:30:01 kernel: [iptables] IN=eth0 OUT= SRC=203.0.113.42 DST=10.0.1.10 PROTO=TCP SPT=45123 DPT=80 SYN
Jan 20 14:30:01 kernel: [iptables] IN=eth0 OUT= SRC=203.0.113.42 DST=10.0.1.10 PROTO=TCP SPT=45124 DPT=80 SYN
Jan 20 14:30:01 kernel: [iptables] IN=eth0 OUT= SRC=203.0.113.42 DST=10.0.1.10 PROTO=TCP SPT=45125 DPT=80 SYN
... (97 more events within the same second) ...
Jan 20 14:30:02 kernel: [iptables] IN=eth0 OUT= SRC=203.0.113.42 DST=10.0.1.10 PROTO=TCP SPT=45223 DPT=80 SYN
... (continued for 60 seconds at ~150 events/second) ...
```

A single source IP (203.0.113.42) generates approximately 150 connection attempts per second to the web server (10.0.1.10) on port 80.

---

## Detection Walkthrough

| Step | Operation | Result |
|---|---|---|
| Normalize | Parse iptables format, extract fields | ~9,000 `UnifiedEvent` records from attacker |
| Group | Group by SourceIP = 203.0.113.42 | Single group with ~9,000 events |
| Sort | Order by timestamp | Events in chronological order |
| Window T=0 | end=0, start=0, window=[event 0], count=1 | Below threshold |
| Window T=99 | end=99, start=0, window=[events 0-99], count=100 | Meets High threshold (100 events / 60s) |
| Detect | windowCount (100) >= FloodMinEvents (100) | Finding created, inFinding = true |
| Burst tracking | Window count stays >= 100 for 60s | Finding extended, peakCount updated to ~9,000 |

The detector fires after just 100 events — within the first second of the attack — because the attacker is generating events far faster than the threshold requires.

---

## The Finding

```json
{
  "Category": "Flood",
  "Severity": "High",
  "SourceHost": "203.0.113.42",
  "Target": "multiple hosts/ports",
  "TimeRangeStart": "2026-01-20T14:30:01",
  "TimeRangeEnd": "2026-01-20T14:31:01",
  "ShortDescription": "Flood detected from 203.0.113.42",
  "Details": "Detected ~9000 events within 60 seconds."
}
```

The `TimeRangeStart` marks when the threshold was first crossed, while `TimeRangeEnd` marks the end of the burst. The finding captures the full duration and peak event rate of the attack, not just the first qualifying window.

---

## Design Rationale

The detector fires at 100 events (High profile) and continues tracking the burst. The `inFinding` state keeps extending the same finding as the window count stays above threshold, updating the `peakCount` counter. The final finding captures the full duration and peak event rate of the attack.

The `"multiple hosts/ports"` target is generic because the detector does not filter or aggregate by destination — it counts all events from the source, regardless of where they're directed.

---

## Security Value

| Aspect | Value |
|---|---|
| Detection speed | Alert fires within 1 second of attack start |
| Actionability | Source IP is immediately blockable at the firewall |
| Scalability | Processes all events per source; the inner loop is O(n) with O(1) per-event work |
| False positive risk | Low — 100 events in 60 seconds from a single source is abnormal in most networks |
| Forensic value | Time range enables analysts to pull full attack timeline |

---

## Security Takeaways

- The detector catches floods at the earliest possible moment — as soon as the threshold is crossed
- Burst-aware tracking prevents duplicate findings while still capturing repeated attack episodes from the same source
- The inner loop is allocation-free — stack-based arithmetic and integer counting avoid heap allocations during scanning, even when processing thousands of attack events
- One alert per burst gives operators a clean action item: block this IP, investigate the target
