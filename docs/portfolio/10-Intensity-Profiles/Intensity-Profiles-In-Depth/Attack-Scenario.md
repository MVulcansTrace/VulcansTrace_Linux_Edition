# Intensity Profiles — Attack Scenario

## Security Problem

The same log data can yield vastly different analysis results depending on profile selection. This scenario demonstrates how a moderately aggressive port scan — 12 distinct ports in 5 minutes — is invisible at Low intensity, detected at Medium, and produces richer contextual findings at High.

---

## Worked Example

### Synthetic iptables Log Data

```
Jan 30 22:10:01 kernel: [iptables] IN=eth0 OUT=eth1 SRC=10.0.1.50 DST=192.168.1.10 PROTO=TCP SPT=49152 DPT=22
Jan 30 22:10:05 kernel: [iptables] IN=eth0 OUT=eth1 SRC=10.0.1.50 DST=192.168.1.10 PROTO=TCP SPT=49153 DPT=80
Jan 30 22:10:09 kernel: [iptables] IN=eth0 OUT=eth1 SRC=10.0.1.50 DST=192.168.1.10 PROTO=TCP SPT=49154 DPT=443
Jan 30 22:10:13 kernel: [iptables] IN=eth0 OUT=eth1 SRC=10.0.1.50 DST=192.168.1.10 PROTO=TCP SPT=49155 DPT=3306
Jan 30 22:10:17 kernel: [iptables] IN=eth0 OUT=eth1 SRC=10.0.1.50 DST=192.168.1.10 PROTO=TCP SPT=49156 DPT=5432
Jan 30 22:10:21 kernel: [iptables] IN=eth0 OUT=eth1 SRC=10.0.1.50 DST=192.168.1.10 PROTO=TCP SPT=49157 DPT=8080
Jan 30 22:10:25 kernel: [iptables] IN=eth0 OUT=eth1 SRC=10.0.1.50 DST=192.168.1.10 PROTO=TCP SPT=49158 DPT=8443
Jan 30 22:10:29 kernel: [iptables] IN=eth0 OUT=eth1 SRC=10.0.1.50 DST=192.168.1.10 PROTO=TCP SPT=49159 DPT=1433
Jan 30 22:10:33 kernel: [iptables] IN=eth0 OUT=eth1 SRC=10.0.1.50 DST=192.168.1.10 PROTO=TCP SPT=49160 DPT=1521
Jan 30 22:10:37 kernel: [iptables] IN=eth0 OUT=eth1 SRC=10.0.1.50 DST=192.168.1.10 PROTO=TCP SPT=49161 DPT=27017
Jan 30 22:10:41 kernel: [iptables] IN=eth0 OUT=eth1 SRC=10.0.1.50 DST=192.168.1.10 PROTO=TCP SPT=49162 DPT=6379
Jan 30 22:10:45 kernel: [iptables] IN=eth0 OUT=eth1 SRC=10.0.1.50 DST=192.168.1.10 PROTO=TCP SPT=49163 DPT=9200
```

Twelve events from host 10.0.1.50, each hitting a different port on 192.168.1.10 over 44 seconds. The ports include SSH (22), HTTP (80), HTTPS (443), MySQL (3306), PostgreSQL (5432), and several database and middleware ports — a classic service enumeration scan.

---

## Detection Walkthrough — Low Profile

| Step | Operation | Result |
|---|---|---|
| Normalize | Parse iptables format | 12 UnifiedEvent records |
| Resolve profile | `GetProfile(IntensityLevel.Low)` | PortScanMinPorts = **30** |
| Port scan detection | 12 unique ports < 30 threshold | **Not detected** |
| Novelty | EnableNovelty = false | **Skipped** |
| C2 detection | EnableC2Detection = false | **Skipped** |
| MinSeverityToShow | Severity.High | Only High/Critical findings pass |
| **Result** | | **0 findings** |

The scan is too small for Low profile thresholds. Only scans of 30+ ports would trigger detection.

---

## Detection Walkthrough — Medium Profile

| Step | Operation | Result |
|---|---|---|
| Normalize | Parse iptables format | 12 UnifiedEvent records |
| Resolve profile | `GetProfile(IntensityLevel.Medium)` | PortScanMinPorts = **15** |
| Port scan detection | 12 unique ports < 15 threshold | **Not detected** |
| Novelty | EnableNovelty = true, but internal traffic | No external singletons |
| MinSeverityToShow | Severity.Medium | Medium+ findings pass |

Wait — 12 ports is still below the Medium threshold of 15. Let's add a slightly larger scan:

```
(Plus 3 more ports: 5985, 5986, 3389)
```

Now 15 unique ports in 5 minutes:

| Step | Operation | Result |
|---|---|---|
| Port scan detection | 15 unique ports >= 15 threshold | **Detected** |
| Finding severity | Medium (port scan) | Passes MinSeverityToShow = Medium |
| **Result** | | **1 finding: Port Scan** |

The scan is detected at Medium but not at Low — demonstrating the 2x threshold progression.

---

## Detection Walkthrough — High Profile

| Step | Operation | Result |
|---|---|---|
| Resolve profile | `GetProfile(IntensityLevel.High)` | PortScanMinPorts = **8** |
| Port scan detection | 12 unique ports >= 8 threshold | **Detected** |
| MinSeverityToShow | Severity.Info | All findings pass |

Even without the additional 3 ports, the original 12-port scan is detected at High intensity because the threshold is only 8 ports. The High profile catches this attack that Low and Medium would miss.

---

## Profile Comparison Summary

| Profile | PortScanMinPorts | 12-port scan detected? | Additional detectors active |
|---|---|---|---|
| Low | 30 | No | None beyond baseline |
| Medium | 15 | No (borderline) | Novelty, KernelModule, C2, PrivEsc |
| High | 8 | **Yes** | All 13 detectors |

---

## Design Rationale

This scenario demonstrates why the three-tier model matters:

- **Low profile** is designed for high-traffic networks where only obvious, high-confidence threats should surface. A 12-port scan could be a vulnerability scanner or automated tool — not necessarily an attack.
- **Medium profile** balances coverage and noise. It activates deep inspection detectors (C2, kernel module, privilege escalation) that provide context the baseline detectors cannot.
- **High profile** catches subtle threats like small-scale reconnaissance. The 8-port threshold means even minimal service enumeration is flagged.

The same log data, three different analytical outcomes — all controlled by a single profile selection.

---

## Security Value

| Aspect | Value |
|---|---|
| Threshold progression | Roughly 2x sensitivity increase per tier |
| Detector activation | 6 additional detectors activate at Medium and High |
| Output filtering | MinSeverityToShow ensures analysts see appropriate detail |
| Reproducibility | Same log + same profile = identical results |
| Analyst control | Single selection controls 20+ parameters |

---

## Security Takeaways

- A 12-port service enumeration scan is invisible at Low, borderline at Medium, and clearly detected at High — demonstrating why profile selection matters
- The threshold progression (30 → 15 → 8) is designed so that each tier catches attacks the previous tier misses
- MinSeverityToShow acts as a second filter: even if a Medium-severity finding is produced at Low intensity, it is filtered from output
- The 6 advanced detectors (Novelty, KernelModule, InterfaceHopping, UnusualPacketSize, C2, PrivilegeEscalation) that activate at Medium provide contextual findings that complement the baseline scan detection
- Profile selection is the analyst's primary tool for trading coverage against noise — and every parameter changes coherently as a unit
