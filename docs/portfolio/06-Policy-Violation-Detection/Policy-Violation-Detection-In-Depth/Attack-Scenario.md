# Policy Violation Detection — Attack Scenario

## Security Problem

An attacker has compromised an internal server (10.0.1.25) and needs to exfiltrate stolen database credentials to an external server. They attempt to use FTP (port 21) to transfer the data, assuming the security team is only monitoring HTTP and HTTPS traffic.

---

## Worked Example

### Synthetic iptables Log Data

```
Jan 25 03:14:01 kernel: [iptables] IN=eth0 OUT=eth1 SRC=10.0.1.25 DST=93.184.216.34 PROTO=TCP SPT=53120 DPT=21
Jan 25 03:14:02 kernel: [iptables] IN=eth0 OUT=eth1 SRC=10.0.1.25 DST=93.184.216.34 PROTO=TCP SPT=53121 DPT=21
Jan 25 03:14:03 kernel: [iptables] IN=eth0 OUT=eth1 SRC=10.0.1.25 DST=93.184.216.34 PROTO=TCP SPT=53122 DPT=21
```

Three FTP connection attempts from an internal server (10.0.1.25) to an external IP (93.184.216.34) — likely a file transfer and its data channel connections.

---

## Detection Walkthrough

| Step | Operation | Result |
|---|---|---|
| Normalize | Parse iptables format, extract fields | 3 `UnifiedEvent` records |
| Guard | `EnablePolicy` is true, events not empty | Continue |
| Build set | `HashSet<int>` from [21, 23, 445] | Disallowed = {21, 23, 445} |
| Event 1 | Source 10.0.1.25 = internal ✓, Dest 93.184.216.34 = external ✓, Port 21 = disallowed ✓ | Added to group (10.0.1.25, 21) |
| Event 2 | Source 10.0.1.25 = internal ✓, Dest 93.184.216.34 = external ✓, Port 21 = disallowed ✓ | Added to group (10.0.1.25, 21) |
| Event 3 | Source 10.0.1.25 = internal ✓, Dest 93.184.216.34 = external ✓, Port 21 = disallowed ✓ | Added to group (10.0.1.25, 21) |
| Emit | Group (10.0.1.25, 21) has 3 events ≥ minEvents (1) | One finding emitted with aggregated counts |

All three events are collected into a single group, producing one finding that captures the full scope of the violation.

---

## The Finding

```json
{
  "Id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "Category": "PolicyViolation",
  "Severity": "High",
  "SourceHost": "10.0.1.25",
  "Target": "93.184.216.34:21",
  "TimeRangeStart": "2026-01-25T03:14:01",
  "TimeRangeEnd": "2026-01-25T03:14:03",
  "ShortDescription": "Disallowed outbound port 21 from 10.0.1.25",
  "Details": "3 outbound connection(s) to 1 destination(s) on disallowed port 21 from 10.0.1.25."
}
```

> **Note:** The `Id` field is a unique GUID auto-generated for every finding. The timestamps lack timezone suffixes because iptables logs do not include timezone information — the `DateTimeKind` depends on parser behavior at normalization time.

One finding is produced, aggregating all three events. The `TimeRangeStart` and `TimeRangeEnd` span the full duration of the violation (03:14:01 to 03:14:03), and the `Details` field reports the total connection count and distinct destination count for forensic context.

---

## Design Rationale

The detector aggregates all three events into a single finding because they share the same `(SourceIP, DstPort)` pair. The finding alerts the team with the total connection count (3) and the time span, confirming ongoing exfiltration rather than a one-time misconfiguration.

The 3:14 AM timestamp is itself suspicious — automated backup jobs run on schedules, but FTP connections to unfamiliar external IPs at 3 AM are almost certainly malicious.

---

## Security Value

| Aspect | Value |
|---|---|
| Detection confidence | Very high — outbound FTP from an internal server is almost never legitimate |
| Exfiltration disruption | Finding enables immediate blocking of the external destination |
| Forensic timeline | Single finding with min/max timestamps and connection count establishes the duration and frequency of exfiltration |
| Compliance value | Documented evidence of policy enforcement for audit purposes |
| Attacker attribution | In a real scenario, the external IP can be investigated, blocked, and reported |

---

## Security Takeaways

- The filter catches every violation group — there is no sliding window to miss, and the default threshold of 1 means all groups are reported
- FTP to an external IP at 3 AM from a database server is a near-certain exfiltration indicator
- One aggregated finding with event counts and time ranges provides full forensic context without alert fatigue
- The disallowed port list is easily extended to cover environment-specific prohibited protocols
