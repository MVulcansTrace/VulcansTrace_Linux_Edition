using System;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Evidence.Formatters;
using Xunit;

namespace VulcansTrace.Linux.Tests.Evidence;

public class CsvFormatterTests
{
    [Fact]
    public void ToCsv_EscapesFieldsAndIncludesWarnings()
    {
        var formatter = new CsvFormatter();
        var result = new AnalysisResult
        {
            Findings =
            [
                new Finding
                {
                    Category = "Cat,1",
                    Severity = Severity.Medium,
                    SourceHost = "192.168.1.2",
                    Target = "10.0.0.5",
                    TimeRangeStart = DateTime.UnixEpoch,
                    TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
                    ShortDescription = "desc \"quoted\" value",
                    Details = "detail",
                    RuleId = "FW-001"
                }
            ],
            Warnings = ["=cmd|bad"]
        };

        var csv = formatter.ToCsv(result);

        Assert.Contains("RuleId,Category,Severity,SourceHost,Target,TimeStart,TimeEnd,ShortDescription", csv);
        Assert.Contains("FW-001", csv);
        Assert.Contains("\"Cat,1\"", csv);
        Assert.Contains("\"desc \"\"quoted\"\" value\"", csv);
        Assert.Contains("Warnings", csv);
        Assert.Contains("'=cmd|bad", csv);
    }

    [Fact]
    public void ToCsv_EmptyFindings_ProducesHeaderOnly()
    {
        var formatter = new CsvFormatter();
        var result = new AnalysisResult
        {
            Findings = []
        };

        var csv = formatter.ToCsv(result);

        Assert.Contains("Category,Severity,SourceHost", csv);
        Assert.DoesNotContain("192.168", csv);
    }

    [Fact]
    public void ToCsv_WarningsOnly_NoFindings()
    {
        var formatter = new CsvFormatter();
        var result = new AnalysisResult
        {
            Findings = [],
            Warnings = ["test warning"]
        };

        var csv = formatter.ToCsv(result);

        Assert.Contains("Warnings", csv);
        Assert.Contains("test warning", csv);
    }

    [Theory]
    [InlineData("=formula")]
    [InlineData("+formula")]
    [InlineData("-formula")]
    [InlineData("@formula")]
    public void ToCsv_FormulaInjection_PreventsDangerousPrefixes(string dangerous)
    {
        var formatter = new CsvFormatter();
        var result = new AnalysisResult
        {
            Findings =
            [
                new Finding
                {
                    Category = dangerous,
                    Severity = Severity.Low,
                    SourceHost = dangerous,
                    Target = dangerous,
                    TimeRangeStart = DateTime.UnixEpoch,
                    TimeRangeEnd = DateTime.UnixEpoch,
                    ShortDescription = dangerous,
                    Details = "detail"
                }
            ]
        };

        var csv = formatter.ToCsv(result);

        Assert.DoesNotContain("," + dangerous + ",", csv);
    }

    [Fact]
    public void ToCsv_DateTimeMinValue_HandlesBoundaryDate()
    {
        var formatter = new CsvFormatter();
        var result = new AnalysisResult
        {
            Findings =
            [
                new Finding
                {
                    Category = "Test",
                    Severity = Severity.Low,
                    SourceHost = "192.168.1.1",
                    Target = "10.0.0.1",
                    TimeRangeStart = DateTime.MinValue,
                    TimeRangeEnd = DateTime.MinValue,
                    ShortDescription = "test",
                    Details = "detail"
                }
            ]
        };

        var csv = formatter.ToCsv(result);

        Assert.Contains("0001-01-01", csv);
    }

    [Fact]
    public void ToCsv_CarriageReturnPrefix_PreventsFormulaInjection()
    {
        var formatter = new CsvFormatter();
        var result = new AnalysisResult
        {
            Findings =
            [
                new Finding
                {
                    Category = "Cat",
                    Severity = Severity.Low,
                    SourceHost = "192.168.1.1",
                    Target = "10.0.0.1",
                    TimeRangeStart = DateTime.UnixEpoch,
                    TimeRangeEnd = DateTime.UnixEpoch,
                    ShortDescription = "test",
                    Details = "detail"
                }
            ],
            Warnings = ["\rformula"]
        };

        var csv = formatter.ToCsv(result);

        Assert.Contains("'\rformula", csv);
    }

    [Theory]
    [InlineData(" =formula")]
    [InlineData("\t=formula")]
    [InlineData("\n=formula")]
    public void ToCsv_FormulaAfterLeadingWhitespace_PreventsFormulaInjection(string dangerous)
    {
        var formatter = new CsvFormatter();
        var result = new AnalysisResult
        {
            Findings = [],
            Warnings = [dangerous]
        };

        var csv = formatter.ToCsv(result);

        Assert.Contains("'" + dangerous, csv);
    }

    [Fact]
    public void ToSuppressionCsv_IncludesFingerprint()
    {
        var formatter = new CsvFormatter();
        var result = new AnalysisResult
        {
            ActiveSuppressions =
            [
                new SuppressionSummary
                {
                    RuleId = "FW-001",
                    Target = "INPUT",
                    Fingerprint = "fp1",
                    Reason = "Known exposure",
                    CreatedAt = DateTime.UnixEpoch
                }
            ]
        };

        var csv = formatter.ToSuppressionCsv(result);

        Assert.Contains("RuleId,Target,Fingerprint,Reason,CreatedAt,ExpiresAt,ReviewDate", csv);
        Assert.Contains("FW-001,INPUT,fp1,Known exposure", csv);
    }
}
