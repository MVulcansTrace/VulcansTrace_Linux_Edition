using VulcansTrace.Linux.Core.Compliance;
using Xunit;

namespace VulcansTrace.Linux.Tests.Core;

public class CisFamilyResolverTests
{
    [Theory]
    [InlineData("CIS 4.5", "4")]
    [InlineData("CIS 4.5.1", "4")]
    [InlineData("CIS 10.1", "10")]
    [InlineData("CIS 1.1", "1")]
    [InlineData("cis 3.2", "3")]
    [InlineData("CIS 5", "5")]
    public void ExtractFamilyId_ValidId_ReturnsFamilyNumber(string controlId, string expectedFamilyId)
    {
        var result = CisFamilyResolver.ExtractFamilyId(controlId);
        Assert.Equal(expectedFamilyId, result);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("NIST 4.5")]
    [InlineData("4.5")]
    [InlineData("CIS 4.x")]
    [InlineData("CIS 4.1 trailing")]
    [InlineData("Some random text")]
    public void ExtractFamilyId_InvalidId_ReturnsNull(string? controlId)
    {
        var result = CisFamilyResolver.ExtractFamilyId(controlId!);
        Assert.Null(result);
    }

    [Theory]
    [InlineData("1", "Inventory and Control of Enterprise Assets")]
    [InlineData("2", "Inventory and Control of Software Assets")]
    [InlineData("3", "Data Protection")]
    [InlineData("4", "Secure Configuration of Enterprise Assets and Software")]
    [InlineData("5", "Account Management")]
    [InlineData("6", "Access Control Management")]
    [InlineData("7", "Continuous Vulnerability Management")]
    [InlineData("8", "Audit Log Management")]
    [InlineData("9", "Email and Web Browser Protections")]
    [InlineData("10", "Malware Defenses")]
    [InlineData("11", "Data Recovery")]
    [InlineData("12", "Network Infrastructure Management")]
    [InlineData("13", "Network Monitoring and Defense")]
    [InlineData("14", "Security Awareness and Skills Training")]
    [InlineData("15", "Service Provider Management")]
    [InlineData("16", "Application Software Security")]
    [InlineData("17", "Incident Response Management")]
    [InlineData("18", "Penetration Testing")]
    public void GetFamilyName_KnownFamily_ReturnsName(string familyId, string expectedName)
    {
        var result = CisFamilyResolver.GetFamilyName(familyId);
        Assert.Equal(expectedName, result);
    }

    [Theory]
    [InlineData("99")]
    [InlineData("0")]
    [InlineData("abc")]
    public void GetFamilyName_UnknownFamily_ReturnsOther(string familyId)
    {
        var result = CisFamilyResolver.GetFamilyName(familyId);
        Assert.Equal("Other", result);
    }

    [Fact]
    public void ResolveFamilyName_ValidId_ReturnsFullName()
    {
        var result = CisFamilyResolver.ResolveFamilyName("CIS 4.5");
        Assert.Equal("Secure Configuration of Enterprise Assets and Software", result);
    }

    [Fact]
    public void ResolveFamilyName_InvalidId_ReturnsNull()
    {
        var result = CisFamilyResolver.ResolveFamilyName("NIST 4.5");
        Assert.Null(result);
    }
}
