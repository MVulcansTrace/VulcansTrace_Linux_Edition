using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Core.Live;

namespace VulcansTrace.Linux.Engine.Live;

/// <summary>
/// Reads structured firewall events from the netfilter NFLOG subsystem via AF_NETLINK.
/// Requires root privileges or CAP_NET_ADMIN, plus an active iptables/nftables NFLOG rule.
/// </summary>
public sealed class NflogEventSource : IEventSource, IDisposable
{
    private const byte NfnlSubsysUlog = 4;
    private const byte NfulnlMsgConfig = 1;
    private const ushort NfulnlConfigMessageType = (NfnlSubsysUlog << 8) | NfulnlMsgConfig;
    private const ushort NfulaHwAddr = 8;
    private const ushort NfulaPayload = 9;
    private const ushort NfulaPrefix = 10;
    private const ushort NfulaUid = 11;
    private const ushort NfulaCfgCmd = 1;
    private const ushort NfulaCfgMode = 2;
    private const byte NfulnlCfgCmdBind = 1;
    private const byte NfulnlCfgCmdPfBind = 3;
    private const byte NfulnlCopyPacket = 2;

    private readonly ushort _nflogGroup;
    private int _fd = -1;
    private bool _disposed;

    public string DisplayName => "NFLOG Netlink (AF_NETLINK)";

    public bool IsAvailable => NativeSocket.IsRoot() || NativeSocket.HasEffectiveCapability(NativeSocket.CapNetAdmin);

    public string? UnavailabilityReason => IsAvailable ? null : "Requires root privileges or CAP_NET_ADMIN";

    /// <summary>
    /// Initializes a new instance of the <see cref="NflogEventSource"/> class.
    /// </summary>
    /// <param name="nflogGroup">NFLOG group number to bind to (default 1).</param>
    public NflogEventSource(ushort nflogGroup = 1)
    {
        _nflogGroup = nflogGroup;
    }

    public async IAsyncEnumerable<UnifiedEvent> StreamAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!IsAvailable)
        {
            throw new InvalidOperationException(UnavailabilityReason ?? "NFLOG source is not available.");
        }

        _fd = NativeSocket.socket(NativeSocket.AF_NETLINK, NativeSocket.SOCK_DGRAM, NativeSocket.NETLINK_NETFILTER);
        if (_fd < 0)
        {
            var errno = NativeSocket.GetErrno();
            throw new InvalidOperationException($"Failed to create AF_NETLINK socket (errno={errno}).");
        }

        try
        {
            // Bind the local netlink socket. NFLOG group subscription happens
            // through NFULNL_MSG_CONFIG messages, not sockaddr_nl.nl_groups.
            var addr = new sockaddr_nl
            {
                nl_family = NativeSocket.AF_NETLINK,
                nl_pid = 0,
                nl_groups = 0
            };

            int addrSize = Marshal.SizeOf<sockaddr_nl>();
            IntPtr addrPtr = Marshal.AllocHGlobal(addrSize);
            try
            {
                Marshal.StructureToPtr(addr, addrPtr, false);
                if (NativeSocket.bind(_fd, addrPtr, addrSize) < 0)
                {
                    var errno = NativeSocket.GetErrno();
                    throw new InvalidOperationException($"Failed to bind AF_NETLINK socket for NFLOG group {_nflogGroup} (errno={errno}).");
                }
            }
            finally
            {
                Marshal.FreeHGlobal(addrPtr);
            }

            // Send configuration message to request packet payload and metadata
            SendConfigRequest(_fd, _nflogGroup);

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
                        if (errno == 9) // EBADF
                            yield break;

                        await Task.Delay(10, cancellationToken).ConfigureAwait(false);
                        continue;
                    }

                    if (received < 16)
                        continue;

                    ReadOnlySpan<byte> packet = buffer.AsSpan(0, received);
                    if (TryParseNflogMessage(packet, out var evt) && evt != null)
                    {
                        yield return evt;
                    }
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

    /// <summary>
    /// Builds the NFLOG configuration netlink message that requests binding to a group.
    /// Exposed as internal so tests can verify binary construction without a real socket.
    /// </summary>
    internal static byte[] BuildProtocolBindConfigMessage()
    {
        const ushort AF_INET = 2;
        return BuildCommandConfigMessage(AF_INET, NfulnlCfgCmdPfBind);
    }

    internal static byte[] BuildConfigMessage(ushort group)
    {
        const ushort copyRange = ushort.MaxValue;

        // Build netlink message header (16 bytes)
        // nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid
        var msg = new byte[256];
        int offset = 0;

        // Placeholder for nlmsg_len
        offset += 4;

        // nlmsg_type = (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG
        BinaryPrimitives.WriteUInt16LittleEndian(msg.AsSpan(offset, 2), NfulnlConfigMessageType);
        offset += 2;

        // nlmsg_flags = NLM_F_REQUEST
        BinaryPrimitives.WriteUInt16LittleEndian(msg.AsSpan(offset, 2), 1);
        offset += 2;

        // nlmsg_seq = 0
        offset += 4;

        // nlmsg_pid = 0
        offset += 4;

        // nfgenmsg (4 bytes)
        msg[offset++] = 0; // family = AF_UNSPEC
        msg[offset++] = 0; // version = NFNETLINK_V0
        BinaryPrimitives.WriteUInt16BigEndian(msg.AsSpan(offset, 2), group);
        offset += 2;

        WriteAttribute(msg, ref offset, NfulaCfgCmd, [NfulnlCfgCmdBind]);

        Span<byte> mode = stackalloc byte[6];
        BinaryPrimitives.WriteUInt32BigEndian(mode[..4], copyRange);
        mode[4] = NfulnlCopyPacket;
        mode[5] = 0;
        WriteAttribute(msg, ref offset, NfulaCfgMode, mode);

        // Fill in nlmsg_len
        BinaryPrimitives.WriteUInt32LittleEndian(msg.AsSpan(0, 4), (uint)offset);

        return msg.AsSpan(0, offset).ToArray();
    }

    private static void SendConfigRequest(int fd, ushort group)
    {
        SendConfigMessage(fd, BuildProtocolBindConfigMessage());
        SendConfigMessage(fd, BuildConfigMessage(group));
    }

    private static void SendConfigMessage(int fd, byte[] msg)
    {
        GCHandle handle = GCHandle.Alloc(msg, GCHandleType.Pinned);
        var kernel = new sockaddr_nl
        {
            nl_family = NativeSocket.AF_NETLINK,
            nl_pid = 0,
            nl_groups = 0
        };

        int addrSize = Marshal.SizeOf<sockaddr_nl>();
        IntPtr addrPtr = Marshal.AllocHGlobal(addrSize);
        try
        {
            Marshal.StructureToPtr(kernel, addrPtr, false);
            int sent = NativeSocket.sendto(fd, handle.AddrOfPinnedObject(), msg.Length, 0, addrPtr, addrSize);
            if (sent < 0)
            {
                var errno = NativeSocket.GetErrno();
                throw new InvalidOperationException(
                    $"Failed to send NFLOG config request (errno={errno}). " +
                    "Ensure CAP_NET_ADMIN is available and the NFLOG group is valid.");
            }

            if (sent != msg.Length)
            {
                throw new InvalidOperationException($"Incomplete NFLOG config request: sent {sent} of {msg.Length} bytes.");
            }
        }
        finally
        {
            Marshal.FreeHGlobal(addrPtr);
            handle.Free();
        }
    }

    private static byte[] BuildCommandConfigMessage(ushort resourceId, byte command)
    {
        var msg = new byte[64];
        int offset = 0;

        offset += 4;
        BinaryPrimitives.WriteUInt16LittleEndian(msg.AsSpan(offset, 2), NfulnlConfigMessageType);
        offset += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(msg.AsSpan(offset, 2), 1);
        offset += 2;
        offset += 4;
        offset += 4;

        msg[offset++] = 0;
        msg[offset++] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(msg.AsSpan(offset, 2), resourceId);
        offset += 2;

        WriteAttribute(msg, ref offset, NfulaCfgCmd, [command]);
        BinaryPrimitives.WriteUInt32LittleEndian(msg.AsSpan(0, 4), (uint)offset);
        return msg.AsSpan(0, offset).ToArray();
    }

    private static void WriteAttribute(byte[] msg, ref int offset, ushort type, ReadOnlySpan<byte> data)
    {
        int attrStart = offset;
        int attrLen = 4 + data.Length;
        int paddedLen = (attrLen + 3) & ~3;

        BinaryPrimitives.WriteUInt16LittleEndian(msg.AsSpan(offset, 2), (ushort)attrLen);
        offset += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(msg.AsSpan(offset, 2), type);
        offset += 2;
        data.CopyTo(msg.AsSpan(offset, data.Length));
        offset = attrStart + paddedLen;
    }

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

    internal static bool TryParseNflogMessage(ReadOnlySpan<byte> data, out UnifiedEvent? evt)
    {
        evt = null;
        if (data.Length < 16)
            return false;

        int nlmsgLen = (int)BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(0, 4));
        if (nlmsgLen > data.Length)
            return false;

        // Skip nlmsghdr (16 bytes) + nfgenmsg (4 bytes) = 20 bytes header
        int offset = 20;

        string? srcIp = null;
        string? dstIp = null;
        int srcPort = 0;
        int dstPort = 0;
        string protocol = "UNKNOWN";
        string action = "LOGGED";
        int payloadLen = 0;
        byte ttl = 0;
        DateTime? kernelTimestamp = null;
        var linuxSpecific = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        // Parse netlink attributes (TLV format)
        while (offset + 4 <= nlmsgLen)
        {
            int attrLen = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(offset, 2));
            ushort attrType = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(offset + 2, 2));

            if (attrLen < 4 || attrLen > nlmsgLen - offset)
                break;

            int attrDataLen = attrLen - 4;
            var attrData = data.Slice(offset + 4, attrDataLen);

            // Align to 4 bytes
            int paddedLen = (attrLen + 3) & ~3;

            switch (attrType & 0x7FFF)
            {
                case 1: // NFULA_PACKET_HDR
                    if (attrDataLen >= 4)
                    {
                        // hw_protocol (2), hook (1), _pad (1)
                        // payloadLen = BinaryPrimitives.ReadUInt16BigEndian(attrData.Slice(0, 2));
                    }
                    break;

                case 2: // NFULA_MARK
                    if (attrDataLen >= 4)
                    {
                        uint mark = BinaryPrimitives.ReadUInt32BigEndian(attrData);
                        linuxSpecific["MARK"] = mark.ToString();
                    }
                    break;

                case 3: // NFULA_TIMESTAMP
                    if (attrDataLen >= 16)
                    {
                        ulong sec = BinaryPrimitives.ReadUInt64BigEndian(attrData.Slice(0, 8));
                        ulong usec = BinaryPrimitives.ReadUInt64BigEndian(attrData.Slice(8, 8));
                        kernelTimestamp = DateTime.UnixEpoch
                            + TimeSpan.FromSeconds(sec)
                            + TimeSpan.FromMicroseconds(usec);
                    }
                    break;

                case 4: // NFULA_IFINDEX_INDEV
                    if (attrDataLen >= 4)
                    {
                        uint ifindex = BinaryPrimitives.ReadUInt32BigEndian(attrData);
                        linuxSpecific["IN"] = $"ifindex{ifindex}";
                    }
                    break;

                case 5: // NFULA_IFINDEX_OUTDEV
                    if (attrDataLen >= 4)
                    {
                        uint ifindex = BinaryPrimitives.ReadUInt32BigEndian(attrData);
                        linuxSpecific["OUT"] = $"ifindex{ifindex}";
                    }
                    break;

                case NfulaHwAddr:
                    if (attrDataLen >= 8)
                    {
                        var macBytes = attrData.Slice(2, 6);
                        linuxSpecific["MAC"] = BitConverter.ToString(macBytes.ToArray()).Replace("-", ":");
                    }
                    break;

                case NfulaPayload:
                    // Try to parse IP header from payload
                    if (attrDataLen >= 20 && IpHeaderParser.TryParseIpv4(attrData, out var sip, out var dip, out var proto, out ttl, out var iplen, out var payloadOffset))
                    {
                        srcIp = sip;
                        dstIp = dip;
                        protocol = proto == IpHeaderParser.IpProtocolTcp ? "TCP" :
                                   proto == IpHeaderParser.IpProtocolUdp ? "UDP" : "UNKNOWN";
                        payloadLen = iplen;

                        var transport = attrData.Slice(payloadOffset);
                        if (proto == IpHeaderParser.IpProtocolTcp && IpHeaderParser.TryParseTcp(transport, out var tsrc, out var tdst, out var tflags))
                        {
                            srcPort = tsrc;
                            dstPort = tdst;
                            linuxSpecific["FLAGS"] = FormatTcpFlags(tflags);
                        }
                        else if (proto == IpHeaderParser.IpProtocolUdp && IpHeaderParser.TryParseUdp(transport, out var usrc, out var udst, out _))
                        {
                            srcPort = usrc;
                            dstPort = udst;
                            linuxSpecific["FLAGS"] = "UDP";
                        }
                    }
                    break;

                case NfulaPrefix:
                    linuxSpecific["PREFIX"] = System.Text.Encoding.UTF8
                        .GetString(attrData)
                        .TrimEnd('\0');
                    break;

                case NfulaUid:
                    if (attrDataLen >= 4)
                    {
                        uint uid = BinaryPrimitives.ReadUInt32BigEndian(attrData);
                        linuxSpecific["UID"] = uid.ToString();
                    }
                    break;
            }

            offset += paddedLen;
        }

        if (string.IsNullOrEmpty(srcIp) || string.IsNullOrEmpty(dstIp))
            return false;

        linuxSpecific["LEN"] = payloadLen.ToString();
        linuxSpecific["TTL"] = ttl.ToString();

        evt = new UnifiedEvent
        {
            Timestamp = kernelTimestamp ?? DateTime.UtcNow,
            SourceIP = srcIp,
            SourcePort = srcPort,
            DestinationIP = dstIp,
            DestinationPort = dstPort,
            Protocol = protocol,
            Action = action,
            LogFormat = LogFormat.Iptables,
            LinuxSpecific = linuxSpecific
        };

        return true;
    }

}
