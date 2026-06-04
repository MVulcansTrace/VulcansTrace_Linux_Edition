# Live Stream — Real-Time Kernel Telemetry

VulcansTrace can capture live network events directly from the Linux kernel and run the detector pipeline on a rolling window in real time.

## How It Works

1. **Event Source** reads packets or firewall logs from the kernel.
2. **Live Stream Window** buffers events in a thread-safe rolling buffer (default 60 seconds / 10 000 events).
3. **Live Stream Analyzer** periodically runs a dedicated `SentryAnalyzer` instance on the window and emits only *new* findings (deduplicated by fingerprint).
4. **Result Channel** publishes completed `LiveAnalysisResult` records through a bounded `DropOldest` channel (capacity 64), keeping UI updates fresh without stalling analysis.
5. **Live Findings Collection** stores up to 1 000 findings with FIFO eviction; older findings are removed when the cap is reached.
6. **UI** displays live metrics and findings in the **Live Stream** tab via `LiveResultReceived`, which is wired into the main findings grid.

> **Architecture note:** The live stream uses a dedicated `SentryAnalyzer` instance (not the shared one from batch analysis) to avoid concurrency conflicts between background streaming and foreground batch analysis.

## Event Sources

| Source | Kernel API | Privileges | Description |
|--------|-----------|------------|-------------|
| **Synthetic Demo** | N/A | None | Generates realistic traffic for testing (port scans, beaconing, floods). |
| **Kernel Packet Capture** | `AF_PACKET` + classic BPF | Root or `CAP_NET_RAW` | Captures all IPv4 TCP/UDP packets and parses IP/transport headers. |
| **NFLOG Netlink** | `AF_NETLINK` + NFLOG | Root or `CAP_NET_ADMIN` | Reads structured firewall events from the netfilter NFLOG subsystem. |

> **Note:** The desktop UI automatically detects whether root privileges are available and disables kernel sources with a reason message when they are unavailable.

## Source Name Constants

Source names are defined as constants in `LiveStreamViewModel.SourceNames` to prevent fragile string matching:

- `Synthetic Demo Stream`
- `Kernel Packet Capture (AF_PACKET + BPF)`
- `NFLOG Netlink (AF_NETLINK)`

Unknown source names throw at resolution time rather than silently failing.

## Starting Live Capture (Desktop)

1. Open the **Live Stream** tab.
2. Select a source from the dropdown:
   - *Synthetic Demo Stream* — works without root, ideal for demos.
   - *Kernel Packet Capture* — requires root.
   - *NFLOG Netlink* — requires root + an active NFLOG rule.
3. Click **Start**.
4. Watch the metrics panel (events/sec, window size, analysis runs, delta findings).
5. New findings appear in the grid below.
6. Click **Stop** to end the session gracefully (uses `StopAsync()` for clean async shutdown).

## Setting Up NFLOG (Optional)

If you want to use the NFLOG source, add an iptables or nftables rule that sends packets to NFLOG group 1:

```bash
# iptables
sudo iptables -A INPUT -j NFLOG --nflog-group 1

# nftables
sudo nft add rule ip filter input log group 1
```

## Safety & Resource Limits

- **Result backpressure:** Completed analysis results use a `BoundedChannel` with `DropOldest` (capacity 64). If the UI lags, stale result snapshots are dropped rather than blocking analysis.
- **Memory cap:** The rolling window hard-caps at 10 000 events. Oldest events are evicted first.
- **Time window:** Events older than 60 seconds are evicted.
- **Finding cap:** `MaxLiveFindings = 1000`. When exceeded, the oldest finding is removed (FIFO).
- **Finding deduplication:** The same fingerprint is suppressed for 5 minutes to prevent alert spam.
- **Graceful stop:** `StopAsync()` signals cancellation, closes the native socket (unblocking `recv()`), and awaits pipeline completion. Fast `Stop()` is available for reset/Dispose paths.
- **Graceful degradation:** If `AF_PACKET` or `AF_NETLINK` socket creation fails (e.g., missing privileges), the UI shows an error and does not crash.
- **Event delay guard:** `EventDelayMs` is clamped to a minimum of 1 ms to prevent CPU spin when set to 0.

## Architecture Notes

- **Pure C# with P/Invoke:** No separate C compiler, `libbpf`, or eBPF toolchain is required. The build is still `dotnet build`.
- **Classic BPF:** The packet capture source uses `setsockopt(SO_ATTACH_FILTER)` with a pre-built classic BPF program. This is classic socket BPF, not a modern eBPF maps/ring-buffer source.
- **Thread safety:** Event ingestion and analysis run on dedicated background tasks. The UI updates via `Dispatcher.UIThread.Post`.
- **Structured event path:** Since Bug 17, live events bypass stringification and feed directly into `SentryAnalyzer.Analyze(IReadOnlyList<UnifiedEvent>)`, eliminating lossy round-trips through `FormatAsIptablesLog`.
- **Action inference:** Live-captured packets are tagged with action `CAPTURED` (packet capture) or `LOGGED` (NFLOG) instead of the previous `UNKNOWN` default.
- **TTL realism:** Packet capture reads the actual TTL from `packet[8]` rather than hardcoding 64. The synthetic source uses a realistic distribution.
- **NFLOG timestamps:** When the NFLOG payload includes a kernel timestamp (`NFULA_TIMESTAMP`), it is parsed and used as the event `Timestamp` rather than `DateTime.UtcNow`.

## Data Flow Detail

```
IEventSource ──► LiveStreamWindow ──► SentryAnalyzer ──► BoundedChannel ──► LiveResultReceived
     │           (time/count cap)     (dedicated instance)  (DropOldest)      │
     │                                                                        ▼
     └─ PacketCaptureEventSource                                      Findings.AddFinding
     └─ NflogEventSource
     └─ SyntheticEventSource
```

## Bug Fixes and Hardening

The live stream pipeline was hardened through 30 focused bug fixes:

| Bug | Fix | Impact |
|-----|-----|--------|
| 1 | NFLOG `nl_family = AF_NETLINK` (was `AF_PACKET`) | NFLOG source now binds to the correct address family |
| 2 | Removed `NLA_F_NESTED` from flat NFLOG attributes | Attribute parsing no longer misinterprets flat payloads |
| 3 | Double-close race via `Interlocked.Exchange(ref _fd, -1)` | Prevents `ObjectDisposedException` on concurrent stop |
| 4 | Thread `intensity` through the pipeline | Analyzer respects the selected intensity level |
| 5 | `Stop()` → `StopAsync()` with `AsyncRelayCommand` | UI no longer freezes during stop; clean async shutdown |
| 6 | `MaxLiveFindings = 1000` with FIFO eviction | Prevents unbounded memory growth in long-running sessions |
| 7 | `ResolveSource()` caches IDisposable with `ReleaseResolvedSource()` | Eliminates source leak on repeated start/stop cycles |
| 8 | Dedicated `SentryAnalyzer` per live stream | Eliminates concurrency conflicts with batch analysis |
| 9 | Result `BoundedChannel` with `DropOldest(64)` | Fresh UI updates without analysis stalls |
| 10 | TTL from `packet[8]`, synthetic distribution | Realistic TTL values instead of hardcoded 64 |
| 11 | NFLOG kernel timestamp parsed via `NFULA_TIMESTAMP` | Accurate event timestamps from kernel |
| 27 | NFLOG payload/HWADDR/UID constants aligned to `nfnetlink_log.h` | Real kernel NFLOG messages parse correctly |
| 28 | NFLOG `NFULA_CFG_MODE` uses `NFULNL_COPY_PACKET` | Kernel is explicitly asked to deliver packet payloads |
| 29 | Kernel source failures surface through `StreamFaulted` | UI exits running state and shows setup errors |
| 30 | Capability detection checks effective `CAP_NET_RAW` / `CAP_NET_ADMIN` | Non-root capability deployments are recognized |
| 12 | `FormatAsIptablesLog` round-trip test | Verified formatter/parser compatibility |
| 13 | `Start()` null guard (`ArgumentNullException.ThrowIfNull`) | Fails fast on null source |
| 14 | `SendConfigRequest` checks `send()` return + errno | Config request failures are reported, not swallowed |
| 15 | `sock_fprog.len` guard for >65 535 instructions | Prevents truncation of large BPF programs |
| 16 | `EventDelayMs` clamped to `Math.Max(1, delay)` | Prevents CPU spin at zero delay |
| 17 | `Analyze(IReadOnlyList<UnifiedEvent>)` overload | Bypasses lossy string round-trip |
| 18 | Action set to `CAPTURED`/`LOGGED` | Correct action metadata in findings |
| 19 | `LiveResultReceived` wired in `MainViewModel` | Live findings now actually appear in the UI |
| 20 | `SourceNames` constants + throw on unknown | Eliminates fragile string matching |
| 21 | `LiveStreamViewModel` tests (10) | Full VM coverage: start, stop, nulls, unknown source |
| 22 | `TryParseNflogMessage` tests (11) | NFLOG parsing coverage for all field combinations |
| 23 | `BuildConfigMessage` tests (5) | Config message construction verified byte-by-byte |
| 24 | `FormatAsIptablesLog` additional tests (3) | UDP, missing fields, substring coverage |
| 25 | Stress tests (6) | Rapid cycles, dispose-while-running, stuck pipeline timeout |
| 26 | `Start(null, ...)` null guard test | Confirms ArgumentNullException on null source |

## Testing

- Focused unit and integration tests cover all live stream components:
  - `LiveStreamAnalyzerTests` — orchestration, deduplication, null guards, stress
  - `LiveStreamViewModelTests` — VM commands, state transitions, source resolution
  - `NflogEventSourceTests` — parsing, config message construction, field extraction
  - `IpHeaderParserTests` and `ClassicBpfFilterTests` — header parsing and BPF validation
  - `SyntheticEventSourceTests` — generation patterns, seed determinism
  - `LiveStreamWindowTests` — eviction, thread safety, metrics
- Kernel-source tests use conditional skips when root is unavailable so CI passes without privileges.
- The synthetic source can generate port scans, beaconing, and floods on demand for deterministic testing.

## CLI (Future)

A headless live-stream mode for the CLI is planned. For now, live stream is available only in the Avalonia desktop UI.
