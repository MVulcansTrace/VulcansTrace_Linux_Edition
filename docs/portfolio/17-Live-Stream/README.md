# 17 — Live Stream: Real-Time Kernel Telemetry Ingestion

## Overview

This case study covers the addition of a **Live Stream** mode to VulcansTrace Linux Edition. Instead of analyzing static firewall logs, the application can now capture live network events directly from the Linux kernel, buffer them in a rolling window, and run the full detector pipeline in real time.

## Problem

VulcansTrace originally only supported batch analysis of pasted or loaded firewall logs. Security analysts who wanted to monitor live traffic had to:
1. Export logs from `rsyslog` or `journald` to a file.
2. Paste the file into the application.
3. Re-run analysis every time the log changed.

This workflow was too slow for incident response and real-time threat detection.

## Solution

A streaming pipeline was built with three layers to enable real-time analysis:

### 1. Kernel Event Sources (C# P/Invoke)

No separate C binary, `libbpf`, or eBPF toolchain is required; the implementation uses **pure C# with P/Invoke to `libc`**:

- **`AF_PACKET` + classic BPF** — opens a raw packet socket, attaches a kernel BPF filter (`sock_filter`), and parses IP/TCP/UDP headers.
- **`AF_NETLINK` + NFLOG** — binds to a netfilter NFLOG group through `NFULNL_MSG_CONFIG` and reads structured firewall events.
- **Synthetic Demo** — generates realistic traffic patterns without any privileges.

Key design decision: **P/Invoke over separate C helper.**
- Keeps the build entirely within `dotnet build`.
- No `gcc`, `clang`, `libbpf`, or kernel headers required at build time.
- Native structs are mirrored as C# `StructLayout` types for explicit marshalling.

### 2. Rolling Window & Analyzer

- **`LiveStreamWindow`** — thread-safe buffer with dual eviction: time-based (60 s) and count-based (10 000).
- **`LiveStreamAnalyzer`** — consumes `IEventSource`, runs a dedicated `SentryAnalyzer` instance on the window every 5 seconds or 500 events, and deduplicates findings by fingerprint with a 5-minute TTL.
- **`BoundedChannel`** — completed analysis results use `BoundedChannel` with `DropOldest` (capacity 64). If the UI lags, stale result snapshots are dropped rather than blocking analysis.
- **`MaxLiveFindings = 1000`** — the live findings collection uses FIFO eviction. When the cap is reached, the oldest finding is removed.

> **Concurrency isolation:** The live stream uses its own `SentryAnalyzer` instance to avoid conflicts with foreground batch analysis.

### 3. Avalonia UI Integration

- **Live Stream tab** — source selection, start/stop controls, live metrics, and a real-time findings grid.
- **Privilege-aware** — kernel sources are disabled when `geteuid() != 0`, with clear reason text.
- **Async stop** — `StopAsync()` with `AsyncRelayCommand` prevents UI thread freezing during shutdown.
- **Background tasks** — ingestion and analysis run on `TaskCreationOptions.LongRunning` threads; UI updates are marshalled via `Dispatcher.UIThread.Post`.
- **`LiveResultReceived`** — live findings are wired into `MainViewModel.Findings.AddFinding()` so they appear in the shared findings grid.

## Technical Highlights

### Classic BPF Socket Filter

```csharp
// Pre-built classic BPF program: accept only TCP or UDP
sock_filter[] filter =
{
    new() { code = 0x30, jt = 0, jf = 0, k = 9 },      // ldb [9]  (IP protocol)
    new() { code = 0x15, jt = 2, jf = 0, k = 6 },      // jeq #6   (TCP)
    new() { code = 0x15, jt = 1, jf = 0, k = 17 },     // jeq #17  (UDP)
    new() { code = 0x06, jt = 0, jf = 0, k = 0 },      // ret #0   (drop)
    new() { code = 0x06, jt = 0, jf = 0, k = 65535 },  // ret #-1  (accept)
};
```

This is a genuine classic Berkeley Packet Filter program executed by the kernel. It is intentionally simpler than modern eBPF: no maps, helpers, or ring buffers are loaded.

### Zero-Copy Header Parsing

IP, TCP, and UDP headers are parsed using `BinaryPrimitives.ReadUInt16BigEndian` on `ReadOnlySpan<byte>` slices. No unsafe code or pointer arithmetic is required.

### Cancellation & Resource Safety

- `CancellationToken` propagates through the async pipeline.
- `close(fd)` is called on the native socket when stopping or disposing.
- The blocking `recv()` call is unblocked by socket closure, allowing clean shutdown.
- `Interlocked.Exchange(ref _fd, -1)` prevents double-close race conditions.
- `ResolveSource()` caches the resolved `IEventSource` and releases it via `ReleaseResolvedSource()` to prevent IDisposable leaks on repeated start/stop cycles.

### Structured Event Path (Bug 17)

Live events bypass the lossy `FormatAsIptablesLog` / `LogNormalizer` round-trip. They feed directly into `SentryAnalyzer.Analyze(IReadOnlyList<UnifiedEvent>)`, which preserves all fields without stringification artifacts.

### Action Metadata (Bug 18)

Live-captured packets are tagged with action `CAPTURED` (packet capture) or `LOGGED` (NFLOG) instead of the previous `UNKNOWN` default.

### TTL Realism (Bug 10)

Packet capture reads the actual TTL from `packet[8]`. The synthetic source uses a realistic TTL distribution instead of hardcoding 64.

### NFLOG Timestamp Parsing (Bug 11)

When the NFLOG payload includes a kernel timestamp (`NFULA_TIMESTAMP`), it is parsed and used as the event `Timestamp` rather than `DateTime.UtcNow`.

## Files Added / Modified

| Layer | File | Purpose |
|-------|------|---------|
| Core | `Live/IEventSource.cs` | Abstraction for real-time event sources |
| Core | `Live/LiveAnalysisResult.cs` | Result record with delta findings and metrics |
| Core | `Live/LiveWindowMetrics.cs` | Window statistics |
| Engine | `Live/NativeSocket.cs` | P/Invoke declarations for socket/BPF operations |
| Engine | `Live/IpHeaderParser.cs` | IP/TCP/UDP header parsing |
| Engine | `Live/ClassicBpfFilter.cs` | Pre-built BPF programs and attachment logic |
| Engine | `Live/LiveStreamWindow.cs` | Thread-safe rolling buffer |
| Engine | `Live/SyntheticEventSource.cs` | Demo event generator |
| Engine | `Live/LiveStreamAnalyzer.cs` | Orchestrator: source → window → analysis → dedup |
| Engine | `Live/PacketCaptureEventSource.cs` | `AF_PACKET` + cBPF source |
| Engine | `Live/NflogEventSource.cs` | `AF_NETLINK` NFLOG source |
| Avalonia | `ViewModels/LiveStreamViewModel.cs` | UI logic for live stream |
| Avalonia | `Views/LiveStreamView.axaml` | Live Stream tab XAML |
| Avalonia | `MainWindow.axaml` | Added Live Stream tab |
| Avalonia | `MainViewModel.cs` | Injected LiveStreamViewModel; wired LiveResultReceived |
| Agent | `AgentFactory.cs` | Wires LiveStreamAnalyzer into composition root |
| Tests | 6 new test files | Focused unit and integration tests for all live components |

## Bug Fixes and Hardening

The live stream was hardened through 26 focused bug fixes during code review:

| Bug | Fix |
|-----|-----|
| 1 | NFLOG `nl_family = AF_NETLINK` (was `AF_PACKET`) |
| 2 | Removed `NLA_F_NESTED` from flat NFLOG attributes |
| 3 | Double-close race via `Interlocked.Exchange(ref _fd, -1)` |
| 4 | Thread `intensity` parameter through the full pipeline |
| 5 | `Stop()` → `StopAsync()` with `AsyncRelayCommand` |
| 6 | `MaxLiveFindings = 1000` with FIFO eviction |
| 7 | `ResolveSource()` caches IDisposable with `ReleaseResolvedSource()` |
| 8 | Dedicated `SentryAnalyzer` per live stream |
| 9 | Result `BoundedChannel` with `DropOldest(64)` |
| 10 | TTL from `packet[8]`; synthetic uses realistic distribution |
| 11 | NFLOG kernel timestamp parsed via `NFULA_TIMESTAMP` |
| 27 | NFLOG payload/HWADDR/UID constants aligned to `nfnetlink_log.h` |
| 28 | NFLOG `NFULA_CFG_MODE` requests `NFULNL_COPY_PACKET` payloads |
| 29 | Kernel source failures surface through `StreamFaulted` |
| 30 | Availability checks recognize effective `CAP_NET_RAW` / `CAP_NET_ADMIN` |
| 12 | `FormatAsIptablesLog` round-trip parser test |
| 13 | `Start()` null guard (`ArgumentNullException.ThrowIfNull`) |
| 14 | `SendConfigRequest` checks `send()` return + errno |
| 15 | `sock_fprog.len` guard for >65 535 instructions |
| 16 | `EventDelayMs` clamped to `Math.Max(1, delay)` |
| 17 | `Analyze(IReadOnlyList<UnifiedEvent>)` overload |
| 18 | Action set to `CAPTURED`/`LOGGED` |
| 19 | `LiveResultReceived` wired in `MainViewModel` |
| 20 | `SourceNames` constants + throw on unknown |
| 21 | `LiveStreamViewModel` tests (10) |
| 22 | `TryParseNflogMessage` tests (11) |
| 23 | `BuildConfigMessage` tests (5) |
| 24 | `FormatAsIptablesLog` additional tests (3) |
| 25 | Stress tests (6): rapid cycles, dispose-while-running, stuck pipeline timeout |
| 26 | `Start(null, ...)` null guard test |

## Trade-offs

| Decision | Pros | Cons |
|----------|------|------|
| P/Invoke instead of separate C binary | Single `dotnet build`, easier testing, type-safe structs | More C# boilerplate for marshalling |
| Classic BPF instead of eBPF | No `libbpf`/`clang` dependency, works on stock kernels | Less expressive than eBPF (no maps, no helpers) |
| Rolling window instead of infinite stream | Bounded memory, predictable performance | May miss slow attacks that span > 60 s |
| Fingerprint deduplication | Prevents alert spam | Same attack replayed after TTL creates a new finding |
| DropOldest result channel | Fresh UI updates, no stalls | Can skip stale analysis snapshots under extreme UI lag |
| Dedicated SentryAnalyzer | No concurrency conflicts with batch analysis | Slightly more memory |

## Testing

- Focused unit and integration tests cover synthetic sources, window eviction, header parsing, BPF validation, analyzer deduplication, NFLOG message parsing, config message construction, formatter round-trips, VM state transitions, and stress scenarios.
- Kernel-source tests use conditional skips (`if (!root) return`) so CI passes without privileges.
- The synthetic source can generate port scans, beaconing, and floods on demand for deterministic testing.

## Future Work

- CLI live-stream mode for headless monitoring.
- Merge live findings into the main findings grid and timeline for unified analysis.
- eBPF (modern) source using `libbpf` and pre-compiled object files for richer kernel introspection.
- GeoIP enrichment for live-captured source IPs.
