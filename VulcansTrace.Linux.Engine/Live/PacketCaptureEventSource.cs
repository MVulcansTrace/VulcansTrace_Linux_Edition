using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Core.Live;

namespace VulcansTrace.Linux.Engine.Live;

/// <summary>
/// Captures live IPv4 packets from the kernel using an AF_PACKET socket with a classic BPF filter.
/// Requires root privileges or CAP_NET_RAW.
/// </summary>
public sealed class PacketCaptureEventSource : IEventSource, IDisposable
{
    private readonly string? _interfaceName;
    private readonly sock_filter[]? _bpfProgram;
    private int _fd = -1;
    private bool _disposed;

    public string DisplayName => "Kernel Packet Capture (AF_PACKET + BPF)";

    public bool IsAvailable => NativeSocket.IsRoot() || NativeSocket.HasEffectiveCapability(NativeSocket.CapNetRaw);

    public string? UnavailabilityReason => IsAvailable ? null : "Requires root privileges or CAP_NET_RAW";

    /// <summary>
    /// Initializes a new instance of the <see cref="PacketCaptureEventSource"/> class.
    /// </summary>
    /// <param name="interfaceName">Optional interface name to bind to (e.g., "eth0"). Null captures all interfaces.</param>
    public PacketCaptureEventSource(string? interfaceName = null)
    {
        _interfaceName = interfaceName;
        _bpfProgram = ClassicBpfFilter.TcpOrUdpOnly();
    }

    public async IAsyncEnumerable<UnifiedEvent> StreamAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!IsAvailable)
        {
            throw new InvalidOperationException(UnavailabilityReason ?? "Packet capture is not available.");
        }

        _fd = NativeSocket.socket(NativeSocket.AF_PACKET, NativeSocket.SOCK_DGRAM, Htons(NativeSocket.ETH_P_ALL));
        if (_fd < 0)
        {
            var errno = NativeSocket.GetErrno();
            throw new InvalidOperationException($"Failed to create AF_PACKET socket (errno={errno}).");
        }

        try
        {
            // Bind to interface if specified
            if (!string.IsNullOrEmpty(_interfaceName))
            {
                int ifIndex = GetInterfaceIndex(_fd, _interfaceName);
                if (ifIndex < 0)
                {
                    throw new InvalidOperationException($"Interface '{_interfaceName}' not found.");
                }

                var addr = new sockaddr_ll
                {
                    sll_family = NativeSocket.AF_PACKET,
                    sll_protocol = Htons(NativeSocket.ETH_P_ALL),
                    sll_ifindex = ifIndex
                };

                int addrSize = Marshal.SizeOf<sockaddr_ll>();
                IntPtr addrPtr = Marshal.AllocHGlobal(addrSize);
                try
                {
                    Marshal.StructureToPtr(addr, addrPtr, false);
                    if (NativeSocket.bind(_fd, addrPtr, addrSize) < 0)
                    {
                        var errno = NativeSocket.GetErrno();
                        throw new InvalidOperationException($"Failed to bind to interface '{_interfaceName}' (errno={errno}).");
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(addrPtr);
                }
            }

            // Attach BPF filter
            if (ClassicBpfFilter.AttachFilter(_fd, _bpfProgram!) < 0)
            {
                var errno = NativeSocket.GetErrno();
                throw new InvalidOperationException($"Failed to attach BPF filter (errno={errno}).");
            }

            var buffer = new byte[65535];
            GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            try
            {
                IntPtr bufPtr = handle.AddrOfPinnedObject();

                while (!cancellationToken.IsCancellationRequested)
                {
                    int received = NativeSocket.recv(_fd, bufPtr, buffer.Length, 0);

                    if (cancellationToken.IsCancellationRequested)
                        yield break;

                    if (received < 0)
                    {
                        var errno = NativeSocket.GetErrno();
                        // EAGAIN / EINTR are retryable; EBADF means socket was closed for shutdown
                        if (errno == 9) // EBADF
                            yield break;

                        await Task.Delay(10, cancellationToken).ConfigureAwait(false);
                        continue;
                    }

                    if (received < 20)
                        continue; // Too small for IPv4 header

                    var packet = new ReadOnlySpan<byte>(buffer, 0, received);

                    if (!IpHeaderParser.TryParseIpv4(packet, out var srcIp, out var dstIp, out var protocol, out var ttl, out var ipTotalLength, out var payloadOffset))
                        continue;

                    int srcPort = 0;
                    int dstPort = 0;
                    string flags = "UNKNOWN";

                    var payload = packet.Slice(payloadOffset);

                    if (protocol == IpHeaderParser.IpProtocolTcp && IpHeaderParser.TryParseTcp(payload, out var tcpSrc, out var tcpDst, out var tcpFlags))
                    {
                        srcPort = tcpSrc;
                        dstPort = tcpDst;
                        flags = FormatTcpFlags(tcpFlags);
                    }
                    else if (protocol == IpHeaderParser.IpProtocolUdp && IpHeaderParser.TryParseUdp(payload, out var udpSrc, out var udpDst, out _))
                    {
                        srcPort = udpSrc;
                        dstPort = udpDst;
                        flags = "UDP";
                    }

                    var evt = new UnifiedEvent
                    {
                        Timestamp = DateTime.UtcNow,
                        SourceIP = srcIp,
                        SourcePort = srcPort,
                        DestinationIP = dstIp,
                        DestinationPort = dstPort,
                        Protocol = protocol == IpHeaderParser.IpProtocolTcp ? "TCP" : protocol == IpHeaderParser.IpProtocolUdp ? "UDP" : "UNKNOWN",
                        Action = "CAPTURED",
                        LogFormat = LogFormat.Iptables,
                        LinuxSpecific = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                        {
                            ["FLAGS"] = flags,
                            ["LEN"] = ipTotalLength.ToString(),
                            ["TTL"] = ttl.ToString(),
                            ["MAC"] = "00:00:00:00:00:00"
                        }
                    };

                    yield return evt;
                }
            }
            finally
            {
                handle.Free();
            }
        }
        finally
        {
            int fd = Interlocked.Exchange(ref _fd, -1);
            if (fd >= 0)
            {
                NativeSocket.close(fd);
            }
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        int fd = Interlocked.Exchange(ref _fd, -1);
        if (fd >= 0)
        {
            NativeSocket.close(fd);
        }
    }

    private static ushort Htons(ushort value)
    {
        return (ushort)((value << 8) | (value >> 8));
    }

    private static int GetInterfaceIndex(int fd, string ifName)
    {
        // SIOCGIFINDEX = 0x8933
        const uint SIOCGIFINDEX = 0x8933;

        var ifreq = new IfReq();
        var nameBytes = System.Text.Encoding.ASCII.GetBytes(ifName);
        Buffer.BlockCopy(nameBytes, 0, ifreq.ifr_name, 0, Math.Min(nameBytes.Length, 15));

        int size = Marshal.SizeOf<IfReq>();
        IntPtr ptr = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(ifreq, ptr, false);
            if (ioctl(fd, SIOCGIFINDEX, ptr) < 0)
                return -1;

            var result = Marshal.PtrToStructure<IfReq>(ptr);
            return result.ifr_ifindex;
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
    }

    [DllImport("libc", SetLastError = true)]
    private static extern int ioctl(int fd, uint request, IntPtr arg);

    private static string FormatTcpFlags(byte flags)
    {
        var parts = new List<string>();
        if ((flags & 0x01) != 0) parts.Add("FIN");
        if ((flags & 0x02) != 0) parts.Add("SYN");
        if ((flags & 0x04) != 0) parts.Add("RST");
        if ((flags & 0x08) != 0) parts.Add("PSH");
        if ((flags & 0x10) != 0) parts.Add("ACK");
        if ((flags & 0x20) != 0) parts.Add("URG");
        return parts.Count > 0 ? string.Join(",", parts) : "NONE";
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IfReq
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] ifr_name;
        public int ifr_ifindex;

        public IfReq()
        {
            ifr_name = new byte[16];
        }
    }
}
