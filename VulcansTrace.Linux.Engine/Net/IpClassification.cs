using System.Net;

namespace VulcansTrace.Linux.Engine.Net;

/// <summary>
/// Provides utilities for classifying IP addresses as internal (private) or external (public).
/// </summary>
public static class IpClassification
{
    /// <summary>
    /// Determines whether an IP address is internal or local-use.
    /// </summary>
    /// <param name="ip">The IP address to classify.</param>
    /// <returns>True if the IP is internal or local-use; otherwise, false.</returns>
    public static bool IsInternal(string ip)
    {
        return TryClassify(ip, out var isInternal) && isInternal;
    }

    /// <summary>
    /// Determines whether an IP address is external and publicly routable.
    /// </summary>
    /// <param name="ip">The IP address to classify.</param>
    /// <returns>True if the IP is publicly routable; otherwise, false.</returns>
    public static bool IsExternal(string ip)
    {
        if (!IPAddress.TryParse(ip, out var addr))
        {
            return false;
        }

        if (addr.IsIPv4MappedToIPv6)
        {
            addr = addr.MapToIPv4();
        }

        return addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
            ? IsPublicV4(addr)
            : IsPublicV6(addr);
    }

    /// <summary>
    /// Attempts to classify an IP address as internal/local-use or not.
    /// </summary>
    /// <param name="ip">The IP address to classify.</param>
    /// <param name="isInternal">When this method returns, contains true if the IP is internal or local-use.</param>
    /// <returns>True if the classification was successful; false if the IP format is invalid.</returns>
    public static bool TryClassify(string ip, out bool isInternal)
    {
        if (!IPAddress.TryParse(ip, out var addr))
        {
            isInternal = false;
            return false;
        }

        if (addr.IsIPv4MappedToIPv6)
        {
            addr = addr.MapToIPv4();
        }

        if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            isInternal = IsInternalV6(addr);
            return true;
        }

        isInternal = IsInternalV4(addr);
        return true;
    }

    private static bool IsInternalV4(IPAddress addr)
    {
        var b = addr.GetAddressBytes();
        return b[0] == 10 ||
               b[0] == 127 ||
               b[0] == 0 ||
               (b[0] == 100 && b[1] >= 64 && b[1] <= 127) ||
               (b[0] == 169 && b[1] == 254) ||
               (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
               (b[0] == 192 && b[1] == 168) ||
               (b[0] == 255 && b[1] == 255 && b[2] == 255 && b[3] == 255);
    }

    private static bool IsPublicV4(IPAddress addr)
    {
        var b = addr.GetAddressBytes();
        if (IsInternalV4(addr))
        {
            return false;
        }

        return !(b[0] == 192 && b[1] == 0 && b[2] == 0) &&
               !(b[0] == 192 && b[1] == 0 && b[2] == 2) &&
               !(b[0] == 198 && (b[1] == 18 || b[1] == 19)) &&
               !(b[0] == 198 && b[1] == 51 && b[2] == 100) &&
               !(b[0] == 203 && b[1] == 0 && b[2] == 113) &&
               !(b[0] >= 224 && b[0] <= 239) &&   // multicast (224.0.0.0/4)
               !(b[0] >= 240);                      // reserved + broadcast (240.0.0.0/4)
    }

    /// <summary>
    /// Determines whether an IPv6 address is internal (private network).
    /// </summary>
    /// <param name="addr">The IPv6 address to classify.</param>
    /// <returns>True if the address is internal; otherwise, false.</returns>
    private static bool IsInternalV6(IPAddress addr)
    {
        // Loopback
        if (IPAddress.IPv6Loopback.Equals(addr))
            return true;

        // IPv4-mapped
        if (addr.IsIPv4MappedToIPv6)
            return IsInternal(addr.MapToIPv4().ToString());

        var bytes = addr.GetAddressBytes();

        // Unique Local Address fc00::/7 (0b1111110x)
        if ((bytes[0] & 0xFE) == 0xFC)
            return true;

        // Link-local fe80::/10 (1111 1110 10xx xxxx)
        if (bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80)
            return true;

        return false;
    }

    private static bool IsPublicV6(IPAddress addr)
    {
        var bytes = addr.GetAddressBytes();
        if (IsInternalV6(addr) ||
            addr.IsIPv6Multicast ||
            IPAddress.IPv6Any.Equals(addr) ||
            IPAddress.IPv6Loopback.Equals(addr))
        {
            return false;
        }

        // Public IPv6 unicast space is 2000::/3. Treat other reserved/special
        // prefixes as non-public so detectors do not flag them as internet destinations.
        if ((bytes[0] & 0xE0) != 0x20)
        {
            return false;
        }

        return !IsSpecialGlobalV6(bytes);
    }

    private static bool IsSpecialGlobalV6(byte[] bytes)
    {
        return (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0D && bytes[3] == 0xB8) || // documentation 2001:db8::/32
               (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x00 && bytes[3] == 0x02 && bytes[4] == 0x00 && bytes[5] == 0x00) || // benchmarking 2001:2::/48
               (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x00 && (bytes[3] & 0xF0) == 0x10) || // ORCHID 2001:10::/28
               (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x00 && (bytes[3] & 0xF0) == 0x20);   // ORCHIDv2 2001:20::/28
    }
}
