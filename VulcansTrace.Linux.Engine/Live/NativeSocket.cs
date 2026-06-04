using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;

namespace VulcansTrace.Linux.Engine.Live;

/// <summary>
/// Centralized P/Invoke declarations for Linux raw socket operations used by live stream event sources.
/// All methods delegate directly to libc.
/// </summary>
internal static class NativeSocket
{
    public const int AF_PACKET = 17;
    public const int AF_NETLINK = 16;
    public const int SOCK_DGRAM = 2;
    public const int SOCK_RAW = 3;
    public const int NETLINK_NETFILTER = 12;
    public const int ETH_P_ALL = 0x0003;
    public const int SOL_SOCKET = 1;
    public const int SO_ATTACH_FILTER = 26;
    public const int CapNetAdmin = 12;
    public const int CapNetRaw = 13;

    [DllImport("libc", SetLastError = true)]
    public static extern int socket(int domain, int type, int protocol);

    [DllImport("libc", SetLastError = true)]
    public static extern int close(int fd);

    [DllImport("libc", SetLastError = true)]
    public static extern int bind(int fd, IntPtr addr, int addrLen);

    [DllImport("libc", SetLastError = true)]
    public static extern int setsockopt(int fd, int level, int optName, IntPtr optVal, int optLen);

    [DllImport("libc", SetLastError = true)]
    public static extern int recv(int fd, IntPtr buf, int len, int flags);

    [DllImport("libc", SetLastError = true)]
    public static extern int recvfrom(int fd, IntPtr buf, int len, int flags, IntPtr srcAddr, IntPtr addrlen);

    [DllImport("libc", SetLastError = true)]
    public static extern int send(int fd, IntPtr buf, int len, int flags);

    [DllImport("libc", SetLastError = true)]
    public static extern int sendto(int fd, IntPtr buf, int len, int flags, IntPtr destAddr, int addrLen);

    [DllImport("libc", SetLastError = true)]
    public static extern int geteuid();

    public static int GetErrno() => Marshal.GetLastWin32Error();

    public static bool IsRoot() => geteuid() == 0;

    public static bool HasEffectiveCapability(int capability)
    {
        if (capability < 0 || capability >= 64)
            return false;

        try
        {
            foreach (var line in File.ReadLines("/proc/self/status"))
            {
                if (!line.StartsWith("CapEff:", StringComparison.Ordinal))
                    continue;

                var value = line["CapEff:".Length..].Trim();
                if (!ulong.TryParse(value, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var effectiveCaps))
                    return false;

                return (effectiveCaps & (1UL << capability)) != 0;
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }

        return false;
    }
}

/// <summary>
/// sockaddr_ll for AF_PACKET binding (packet socket address).
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct sockaddr_ll
{
    public ushort sll_family;
    public ushort sll_protocol;
    public int sll_ifindex;
    public ushort sll_hatype;
    public byte sll_pkttype;
    public byte sll_halen;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
    public byte[] sll_addr;
}

/// <summary>
/// sockaddr_nl for AF_NETLINK binding (netlink socket address).
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct sockaddr_nl
{
    public ushort nl_family;
    public ushort nl_pad;
    public uint nl_pid;
    public uint nl_groups;
}

/// <summary>
/// Classic BPF instruction (sock_filter).
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 8)]
internal struct sock_filter
{
    public ushort code;
    public byte jt;
    public byte jf;
    public uint k;
}

/// <summary>
/// Classic BPF program descriptor (sock_fprog).
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct sock_fprog
{
    public ushort len;
    public IntPtr filter;
}
