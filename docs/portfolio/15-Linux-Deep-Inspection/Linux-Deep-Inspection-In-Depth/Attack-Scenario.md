# Attack Scenario: Multi-Signal Linux Attack

## The Security Problem

An advanced attacker targeting a Linux server combines multiple techniques to maximize damage while evading individual detectors. They begin with stealth port scanning using FIN packets, spoof their MAC address to bypass L2 filtering, pivot between network interfaces to probe isolated segments, and exfiltrate data using large packets on non-standard ports. No single detector catches the full attack — the threat is only visible when findings are correlated across the detector suite.

---

## Worked Example

Consider the following synthetic iptables log entries from a multi-stage attack launched by `10.0.0.99` against a Linux server with interfaces `eth0` (DMZ) and `eth1` (internal LAN):

```
kernel: IN=eth0 SRC=10.0.0.99 DST=192.168.1.50 PROTO=TCP SPT=45120 DPT=22 FLAGS=FIN MAC=aa:bb:cc:dd:ee:01 LEN=60
kernel: IN=eth0 SRC=10.0.0.99 DST=192.168.1.50 PROTO=TCP SPT=45121 DPT=80 FLAGS=FIN MAC=aa:bb:cc:dd:ee:01 LEN=60
kernel: IN=eth0 SRC=10.0.0.99 DST=192.168.1.50 PROTO=TCP SPT=45122 DPT=443 FLAGS=FIN MAC=aa:bb:cc:dd:ee:01 LEN=60
kernel: IN=eth0 SRC=10.0.0.99 DST=192.168.1.50 PROTO=TCP SPT=45123 DPT=3306 FLAGS=FIN MAC=aa:bb:cc:dd:ee:01 LEN=60
kernel: IN=eth0 SRC=10.0.0.99 DST=192.168.1.50 PROTO=TCP SPT=45124 DPT=5432 FLAGS=FIN MAC=aa:bb:cc:dd:ee:01 LEN=60
kernel: IN=eth0 SRC=10.0.0.99 DST=192.168.1.50 PROTO=TCP SPT=45125 DPT=8080 FLAGS=FIN MAC=aa:bb:cc:dd:ee:01 LEN=60
kernel: IN=eth0 SRC=10.0.0.99 DST=192.168.1.50 PROTO=TCP SPT=45126 DPT=8443 FLAGS=FIN MAC=aa:bb:cc:dd:ee:01 LEN=60
kernel: IN=eth0 SRC=10.0.0.99 DST=192.168.1.50 PROTO=TCP SPT=45127 DPT=25 FLAGS=FIN MAC=aa:bb:cc:dd:ee:01 LEN=60
kernel: IN=eth0 SRC=10.0.0.99 DST=192.168.1.50 PROTO=TCP SPT=45128 DPT=53 FLAGS=FIN MAC=aa:bb:cc:dd:ee:02 LEN=60
kernel: IN=eth0 SRC=10.0.0.99 DST=192.168.1.50 PROTO=TCP SPT=45129 DPT=110 FLAGS=FIN MAC=aa:bb:cc:dd:ee:02 LEN=60
kernel: IN=eth0 SRC=10.0.0.99 DST=192.168.1.50 PROTO=TCP SPT=45130 DPT=143 FLAGS=FIN MAC=aa:bb:cc:dd:ee:02 LEN=60
kernel: IN=eth0 SRC=10.0.0.99 DST=192.168.1.50 PROTO=TCP SPT=45131 DPT=993 FLAGS=FIN MAC=aa:bb:cc:dd:ee:02 LEN=60
kernel: IN=eth0 SRC=10.0.0.99 DST=192.168.1.50 PROTO=TCP SPT=45132 DPT=995 FLAGS=FIN MAC=aa:bb:cc:dd:ee:02 LEN=60
kernel: IN=eth0 SRC=10.0.0.99 DST=192.168.1.50 PROTO=TCP SPT=45133 DPT=587 FLAGS=FIN MAC=aa:bb:cc:dd:ee:02 LEN=60
kernel: IN=eth0 SRC=10.0.0.99 DST=192.168.1.50 PROTO=TCP SPT=45134 DPT=1723 FLAGS=FIN MAC=aa:bb:cc:dd:ee:02 LEN=60
kernel: IN=eth0 SRC=10.0.0.99 DST=192.168.1.50 PROTO=TCP SPT=45135 DPT=3389 FLAGS=FIN MAC=aa:bb:cc:dd:ee:02 LEN=60
kernel: IN=eth1 SRC=10.0.0.99 DST=10.0.2.15 PROTO=TCP SPT=45200 DPT=445 FLAGS=FIN MAC=aa:bb:cc:dd:ee:02 LEN=60
kernel: IN=eth1 SRC=10.0.0.99 DST=10.0.2.15 PROTO=TCP SPT=45201 DPT=3389 FLAGS=FIN MAC=aa:bb:cc:dd:ee:02 LEN=60
kernel: IN=eth1 SRC=10.0.0.99 DST=10.0.2.20 PROTO=TCP SPT=45300 DPT=4444 LEN=4500 MAC=aa:bb:cc:dd:ee:02
kernel: IN=eth1 SRC=10.0.0.99 DST=10.0.2.20 PROTO=TCP SPT=45301 DPT=4444 LEN=4200 MAC=aa:bb:cc:dd:ee:02
kernel: IN=eth1 SRC=10.0.0.99 DST=10.0.2.20 PROTO=TCP SPT=45302 DPT=4444 LEN=4800 MAC=aa:bb:cc:dd:ee:02
```

---

## Detection Walkthrough

### FlagAnomalyDetector

| Step | Operation | Result |
|---|---|---|
| 1. Guard | `EnableFlagAnomaly = true`, events.Count = 21 | Proceed |
| 2. Protocol filter | 21 TCP events, 0 non-TCP | All analyzed |
| 3. FIN-without-SYN check | Events 1–18 have `FLAGS=FIN` with no SYN | 1 finding emitted (Medium) — all 18 events aggregated by `(SourceIP, AnomalyType)` |
| 4. XMAS check | No FIN+PSH+URG events | No additional findings |

### MacSpoofingDetector

| Step | Operation | Result |
|---|---|---|
| 1. Guard | `EnableMacSpoofing = true`, events.Count = 21 | Proceed |
| 2. Group by SourceIP | All events from `10.0.0.99` | One group |
| 3. Extract distinct MACs | `aa:bb:cc:dd:ee:01` and `aa:bb:cc:dd:ee:02` | 2 MACs found |
| 4. Multi-MAC check | 2 > 1 → suspicious | High-severity finding emitted |

### InterfaceHoppingDetector

| Step | Operation | Result |
|---|---|---|
| 1. Guard | `EnableInterfaceHopping = true`, events.Count = 21 | Proceed |
| 2. Group by SourceIP | All events from `10.0.0.99` | One group |
| 3. Collect interfaces | `eth0` and `eth1` | 2 interfaces found |
| 4. Order chronologically | Events sorted by timestamp | Sequential |
| 5. Rapid-switching check | Event 17 switches eth0 → eth1 within the configured window | Confirmed |
| 6. Emit finding | InterfaceHopping | Medium-severity finding emitted |

### UnusualPacketSizeDetector

| Step | Operation | Result |
|---|---|---|
| 1. Guard | `EnableUnusualPacketSize = true`, events.Count = 21 | Proceed |
| 2. Per-packet: large | Events 19–21 have LEN > 3000 (4500, 4200, 4800) | 1 finding emitted (Medium) — grouped by `(SrcIP, DstIP)` pair |
| 3. Per-packet: small | No packets < 40 bytes | No small-packet findings |
| 4. Aggregate: 18 non-outlier packets | All tuples have < 10 packets each (different destination ports) | No aggregate findings |
| 5. Consistency check | No tuple has ≥ 10 packets | No consistency finding |
| 6. Variance check | No tuple has ≥ 10 packets | No variance finding |

### PortScanDetector (baseline)

| Step | Operation | Result |
|---|---|---|
| 1. Group by SourceIP | All events from `10.0.0.99` | One group |
| 2. Count distinct destination ports | 21 distinct ports | >= 15 threshold |
| 3. Emit finding | PortScan | Medium-severity finding emitted |

---

## Risk Escalation

The `RiskEscalator` groups all findings by `SourceHost` (`10.0.0.99`) and checks for category combinations:

| Correlation Rule | Categories Present | Escalated? |
|---|---|---|
| FlagAnomaly + PortScan | Both present for `10.0.0.99` | **Yes → Critical** |
| MacSpoofing + InterfaceHopping | Both present for `10.0.0.99` | **Yes → Critical** |

All findings for `10.0.0.99` are promoted to **Critical severity**:

```json
[
  { "Category": "FlagAnomaly",   "Severity": "Critical", "SourceHost": "10.0.0.99", ... },
  { "Category": "PortScan",      "Severity": "Critical", "SourceHost": "10.0.0.99", ... },
  { "Category": "MacSpoofing",   "Severity": "Critical", "SourceHost": "10.0.0.99", ... },
  { "Category": "InterfaceHopping", "Severity": "Critical", "SourceHost": "10.0.0.99", ... },
  { "Category": "UnusualPacketSize", "Severity": "Critical", "SourceHost": "10.0.0.99", ... }
]
```

---

## Design Rationale

The attack above demonstrates why independent detectors with downstream correlation outperform monolithic analysis:

1. **FlagAnomalyDetector** catches the FIN scan (1 finding aggregating 18 events) — but alone, this is Medium severity
2. **PortScanDetector** catches the 21-port reconnaissance — but alone, this is Medium severity
3. **RiskEscalator** correlates these into Critical: stealth scanning combined with port enumeration is advanced reconnaissance
4. **MacSpoofingDetector** catches the MAC change — alone, this is High severity (L2 attack)
5. **InterfaceHoppingDetector** catches the eth0 → eth1 pivot — alone, this is Medium severity
6. **RiskEscalator** correlates these into Critical: MAC spoofing combined with interface hopping is a coordinated L2/L3 attack
7. **UnusualPacketSizeDetector** catches the exfiltration packets (3 large + high variance) — additional evidence of data theft

No single detector identified the full attack, but the correlated finding stream tells the complete story: `10.0.0.99` is conducting advanced reconnaissance using stealth techniques while masquerading at L2 and pivoting between network segments, with evidence of data exfiltration via large packets.

---

## Security Value

| Aspect | Value |
|---|---|
| Multi-signal coverage | Five independent detectors catch different facets of the same attack |
| Automated correlation | `RiskEscalator` promotes to Critical without manual triage |
| Actionable attribution | Findings point to `10.0.0.99` with specific evidence per detector |
| Temporal context | Findings include time ranges showing the attack progression |
| L2 + L3 + L4 coverage | MAC (L2), interfaces (L3), flags (L4), packet sizes (payload) |

---

## Security Takeaways

1. A multi-signal attack that evades any single detector is caught by the combination — FIN scans, MAC spoofing, interface pivoting, and large packets each trigger independent findings
2. The `RiskEscalator` is the critical integration point — FlagAnomaly+PortScan and MacSpoofing+InterfaceHopping are both escalated to Critical for this attacker
3. The packet size detector catches the exfiltration phase that connection-based detectors miss — 4500-byte packets to port 4444 are not a scan pattern
4. The MAC spoofing finding provides L2 attribution evidence — `aa:bb:cc:dd:ee:01` and `aa:bb:cc:dd:ee:02` can be traced to physical devices
5. The interface hopping finding proves the attacker pivoted from DMZ (eth0) to internal LAN (eth1), indicating a segmentation breach
