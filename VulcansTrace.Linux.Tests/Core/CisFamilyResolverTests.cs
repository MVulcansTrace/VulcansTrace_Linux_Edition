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
    [InlineData("Some random text")]
    public void ExtractFamilyId_InvalidId_ReturnsNull(string? controlId)
    {
        var result = CisFamilyResolver.ExtractFamilyId(controlId!);
        Assert.Null(result);
    }

    [Theory]
    [InlineData("1", "Initial Setup")]
    [InlineData("2", "Services")]
    [InlineData("3", "Network Configuration")]
    [InlineData("4", "Logging and Auditing")]
    [InlineData("5", "Access, Authentication and Authorization")]
    [InlineData("6", "System Maintenance")]
    [InlineData("7", "Optional Services")]
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
        Assert.Equal("Logging and Auditing", result);
    }

    [Fact]
    public void ResolveFamilyName_InvalidId_ReturnsNull()
    {
        var result = CisFamilyResolver.ResolveFamilyName("NIST 4.5");
        Assert.Null(result);
    }
}
