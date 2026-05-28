using VulcansTrace.Linux.Engine.Net;

namespace VulcansTrace.Linux.Tests.Engine;

public class IpClassificationTests
{
    [Theory]
    [InlineData("10.0.0.1")]
    [InlineData("172.16.0.1")]
    [InlineData("192.168.1.10")]
    [InlineData("127.0.0.1")]
    [InlineData("169.254.10.20")]
    [InlineData("100.64.1.1")]
    [InlineData("::1")]
    [InlineData("fc00::1")]
    [InlineData("fe80::1")]
    public void IsInternal_PrivateAndLocalRanges_ReturnsTrue(string ip)
    {
        Assert.True(IpClassification.IsInternal(ip));
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("169.254.10.20")]
    [InlineData("100.64.1.1")]
    [InlineData("192.0.2.10")]
    [InlineData("198.51.100.10")]
    [InlineData("203.0.113.10")]
    [InlineData("224.0.0.1")]
    [InlineData("240.0.0.1")]
    [InlineData("255.255.255.255")]
    [InlineData("::1")]
    [InlineData("fe80::1")]
    [InlineData("ff02::1")]
    [InlineData("2001:db8::1")]
    [InlineData("64:ff9b::1")]
    [InlineData("100::1")]
    [InlineData("2001:2::1")]
    [InlineData("2001:10::1")]
    [InlineData("2001:20::1")]
    public void IsExternal_NonPublicRanges_ReturnsFalse(string ip)
    {
        Assert.False(IpClassification.IsExternal(ip));
    }

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("1.1.1.1")]
    [InlineData("2001:4860:4860::8888")]
    public void IsExternal_PublicRanges_ReturnsTrue(string ip)
    {
        Assert.True(IpClassification.IsExternal(ip));
    }
}
