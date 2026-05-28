## The Security Problem

An analyst receives an iptables log from a compromised web server. The log contains evidence of a port scan followed by a targeted SSH brute-force attempt. Before any detector can identify the scan pattern, the raw kernel log text must be parsed into structured events with correct IPs, ports, timestamps, and firewall actions.

---

## Worked Example

**Input — raw iptables log:**

```
kernel: Jan 19 10:15:32 webserver IPTABLES-DROP IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=203.0.113.50 DST=192.168.1.10 LEN=60 TOS=0x00 PREC=0x00 TTL=52 ID=44821 DF PROTO=TCP SPT=49152 DPT=22 WINDOW=64240 RES=0x00 SYN
kernel: Jan 19 10:15:32 webserver IPTABLES-DROP IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=203.0.113.50 DST=192.168.1.10 LEN=60 TOS=0x00 PREC=0x00 TTL=52 ID=44822 DF PROTO=TCP SPT=49152 DPT=80 WINDOW=64240 RES=0x00 SYN
kernel: Jan 19 10:15:32 webserver IPTABLES-DROP IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=203.0.113.50 DST=192.168.1.10 LEN=60 TOS=0x00 PREC=0x00 TTL=52 ID=44823 DF PROTO=TCP SPT=49152 DPT=443 WINDOW=64240 RES=0x00 SYN
kernel: Jan 19 10:15:32 webserver IPTABLES-DROP IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=203.0.113.50 DST=192.168.1.10 LEN=60 TOS=0x00 PREC=0x00 TTL=52 ID=44824 DF PROTO=TCP SPT=49152 DPT=3306 WINDOW=64240 RES=0x00 SYN
kernel: Jan 19 10:15:33 webserver IPTABLES-DROP IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=203.0.113.50 DST=192.168.1.10 LEN=60 TOS=0x00 PREC=0x00 TTL=52 ID=44825 DF PROTO=TCP SPT=49153 DPT=22 WINDOW=64240 RES=0x00 SYN
```

---

## Detection Walkthrough

| Stage | Action | Result |
|---|---|---|
| **Size Guard** | Check input length (1,200 chars) | Pass — well under 100M cap |
| **Format Detection** | Scan for `kernel:` + `PROTO=` (any value) | Detected: `LogFormat.Iptables` |
| **Line 1 parse** | Extract SRC/DST/PROTO/SPT/DPT, derive action from `IPTABLES-DROP` prefix | `SourceIP=203.0.113.50, DstPort=22, Action=DROP` |
| **Line 2 parse** | Same source IP, different destination port | `DstPort=80, Action=DROP` |
| **Line 3 parse** | Same source IP, different destination port | `DstPort=443, Action=DROP` |
| **Line 4 parse** | Same source IP, different destination port | `DstPort=3306, Action=DROP` |
| **Line 5 parse** | Same source IP, new source port, back to port 22 | `SrcPort=49153, DstPort=22, Action=DROP` |
| **Result Assembly** | Collect 5 events, 0 errors | `ParseResult { ParsedCount=5, ErrorCount=0 }` |

---

## The Resulting ParseResult

```csharp
ParseResult {
    TotalLines = 5,
    Events = [
        UnifiedEvent {
            Timestamp      = 2026-01-19 10:15:32,  // year inferred from system clock
            SourceIP        = "203.0.113.50",
            DestinationIP   = "192.168.1.10",
            SourcePort      = 49152,
            DestinationPort = 22,
            Protocol        = "TCP",
            Action          = "DROP",
            LogFormat       = Iptables,
            ConnectionKey   = "203.0.113.50:49152-192.168.1.10:22-TCP",
            LinuxSpecific   = {
                InterfaceIn  = "eth0",
                InterfaceOut = "",
                MAC          = "00:11:22:33:44:55",
                Flags        = "SYN",
                Length       = "60",
                TOS          = "0x00",
                TTL          = "52",
                ID           = "44821",
                Window       = "64240"
            },
            RawLine = "kernel: Jan 19 10:15:32 webserver IPTABLES-DROP ..."
        },
        // ... 3 more events (DPT=80, DPT=443, DPT=3306) ...
        UnifiedEvent {
            Timestamp      = 2026-01-19 10:15:33,  // year inferred from system clock
            SourceIP        = "203.0.113.50",
            DestinationIP   = "192.168.1.10",
            SourcePort      = 49153,
            DestinationPort = 22,
            Protocol        = "TCP",
            Action          = "DROP",
            LogFormat       = Iptables,
            ConnectionKey   = "203.0.113.50:49153-192.168.1.10:22-TCP",
            LinuxSpecific   = { /* same structure, ID=44825 */ },
            RawLine = "kernel: Jan 19 10:15:33 webserver IPTABLES-DROP ..."
        }
    ],
    Errors = [],
    ParsedCount = 5,
    ErrorCount = 0
}
```

---

## Design Rationale

The parsed output captures all security-relevant details from the original log lines (including low-value fields like PREC and RES which are extracted to the `LinuxSpecific` dictionary):

- **`Action=DROP`** tells downstream detectors that all five connections were blocked — the port scan was unsuccessful
- **`LinuxSpecific["Flags"] = "SYN"`** indicates these are TCP SYN packets (connection initiation), consistent with a port scan
- **`LinuxSpecific["TTL"] = "52"`** is a network-layer detail that could indicate the attacker's network distance (initial TTL of 64 minus 12 hops)
- **`ConnectionKey`** encodes the 4-tuple (source IP:port, destination IP:port, protocol) so downstream code can reference a connection without re-extracting individual fields
- **`RawLine`** preserves the complete original log for forensic evidence, supporting chain-of-custody requirements

The first four events (ports 22, 80, 443, 3306) represent a port scan. The fifth event (port 22 again with a new source port) suggests the attacker shifted from scanning to targeting SSH specifically — a pattern that the port scan detector and the privilege-escalation detector (which monitors admin ports including 22) can identify.

---

## Security Value

| Aspect | How Normalization Supports It |
|---|---|
| **Port scan detection** | Consistent `DestinationPort` extraction enables grouping by unique destination ports from a single source |
| **Connection tracking** | `ConnectionKey` computed property encodes the full connection 4-tuple for deduplication and session reconstruction |
| **Action verification** | `DROP` action records firewall enforcement status, providing context that analysts can use when triaging findings |
| **Forensic preservation** | `RawLine` retains original evidence for legal or compliance review |
| **Protocol analysis** | `SYN` flag in `LinuxSpecific` indicates the scan technique without re-parsing |

---

## Security Takeaways

1. Normalization transforms five lines of unstructured kernel text into five queryable, validated events via a single `Normalize()` call
2. Action derivation from the `IPTABLES-DROP` prefix correctly identifies all connections as blocked, giving analysts firewall-enforcement context during triage
3. `ConnectionKey` encodes the full connection 4-tuple so downstream code can reference connections without re-extracting fields
4. `LinuxSpecific` metadata (flags, TTL, MAC) provides detection-enriching context without polluting the core event schema
5. `RawLine` preservation supports chain-of-custody requirements — the original evidence is never discarded
