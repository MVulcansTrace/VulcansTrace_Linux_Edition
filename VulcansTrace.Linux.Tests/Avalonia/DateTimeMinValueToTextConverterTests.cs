using System;
using System.Globalization;
using VulcansTrace.Linux.Avalonia.Converters;
using Xunit;

namespace VulcansTrace.Linux.Tests.Avalonia;

/// <summary>
/// Unit tests for <see cref="DateTimeMinValueToTextConverter"/>. The log-diff grid binds
/// BaselineFirstSeen/IncidentFirstSeen through it so that Added events (no baseline first-seen) and
/// Removed events (no incident first-seen) render an em dash instead of the sentinel
/// <c>0001-01-01 00:00:00</c> that <see cref="DateTime.MinValue"/> would otherwise produce.
/// </summary>
public class DateTimeMinValueToTextConverterTests
{
    private static readonly DateTime Sample = new(2026, 7, 25, 14, 30, 5);

    [Fact]
    public void Convert_DateTimeMinValue_Returns_EmDash()
    {
        var converter = new DateTimeMinValueToTextConverter();

        var result = converter.Convert(DateTime.MinValue, typeof(string), null, CultureInfo.InvariantCulture);

        Assert.Equal("—", result);
    }

    [Fact]
    public void Convert_Null_Returns_EmDash()
    {
        var converter = new DateTimeMinValueToTextConverter();

        var result = converter.Convert(null, typeof(string), null, CultureInfo.InvariantCulture);

        Assert.Equal("—", result);
    }

    [Fact]
    public void Convert_ValidDateTime_Returns_Formatted()
    {
        var converter = new DateTimeMinValueToTextConverter();

        var result = converter.Convert(Sample, typeof(string), null, CultureInfo.InvariantCulture);

        Assert.Equal("2026-07-25 14:30:05", result);
    }

    [Fact]
    public void Convert_DateTimeOffsetMinValue_Returns_EmDash()
    {
        var converter = new DateTimeMinValueToTextConverter();

        var result = converter.Convert(DateTimeOffset.MinValue, typeof(string), null, CultureInfo.InvariantCulture);

        Assert.Equal("—", result);
    }

    [Fact]
    public void Convert_UnrecognizedValue_Returns_EmDash()
    {
        var converter = new DateTimeMinValueToTextConverter();

        var result = converter.Convert("not a date", typeof(string), null, CultureInfo.InvariantCulture);

        Assert.Equal("—", result);
    }

    [Fact]
    public void ConvertBack_Always_Throws()
    {
        var converter = new DateTimeMinValueToTextConverter();

        Assert.Throws<NotSupportedException>(
            () => converter.ConvertBack("—", typeof(DateTime), null, CultureInfo.InvariantCulture));
    }
}
