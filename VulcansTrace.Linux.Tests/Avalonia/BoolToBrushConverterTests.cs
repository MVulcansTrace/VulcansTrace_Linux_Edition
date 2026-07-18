using System.Globalization;
using Avalonia.Media;
using VulcansTrace.Linux.Avalonia.Converters;

namespace VulcansTrace.Linux.Tests.Avalonia;

/// <summary>
/// Unit tests for <see cref="BoolToBrushConverter"/>. These lock the
/// direction-sensitive wiring contract: the converter returns TrueBrush when
/// the bound value is true and FalseBrush when it is false. A caller binding
/// to an "is error" bool must set TrueBrush=danger, FalseBrush=success — and
/// these tests ensure the converter itself never silently flips that mapping.
/// </summary>
public class BoolToBrushConverterTests
{
    private static IBrush Brush(string hex) => new SolidColorBrush(Color.Parse(hex));

    [Fact]
    public void Convert_True_Returns_TrueBrush()
    {
        var trueBrush = Brush("#ef4444");
        var falseBrush = Brush("#22c55e");
        var converter = new BoolToBrushConverter { TrueBrush = trueBrush, FalseBrush = falseBrush };

        var result = converter.Convert(true, typeof(IBrush), null, CultureInfo.InvariantCulture);

        Assert.Same(trueBrush, result);
    }

    [Fact]
    public void Convert_False_Returns_FalseBrush()
    {
        var trueBrush = Brush("#ef4444");
        var falseBrush = Brush("#22c55e");
        var converter = new BoolToBrushConverter { TrueBrush = trueBrush, FalseBrush = falseBrush };

        var result = converter.Convert(false, typeof(IBrush), null, CultureInfo.InvariantCulture);

        Assert.Same(falseBrush, result);
    }

    [Fact]
    public void Convert_NonBool_Returns_FallbackBrush()
    {
        var fallback = Brush("#64748b");
        var converter = new BoolToBrushConverter
        {
            TrueBrush = Brush("#ef4444"),
            FalseBrush = Brush("#22c55e"),
            FallbackBrush = fallback,
        };

        var result = converter.Convert("not a bool", typeof(IBrush), null, CultureInfo.InvariantCulture);

        Assert.Same(fallback, result);
    }

    [Fact]
    public void Convert_Null_Returns_FallbackBrush_Or_Null()
    {
        var converter = new BoolToBrushConverter { TrueBrush = Brush("#ef4444"), FalseBrush = Brush("#22c55e") };

        // No FallbackBrush configured → null is the honest result for an unbound state.
        var result = converter.Convert(null, typeof(IBrush), null, CultureInfo.InvariantCulture);

        Assert.Null(result);
    }

    [Fact]
    public void ConvertBack_Always_Throws()
    {
        var converter = new BoolToBrushConverter { TrueBrush = Brush("#ef4444"), FalseBrush = Brush("#22c55e") };

        Assert.Throws<NotSupportedException>(
            () => converter.ConvertBack(Brush("#ef4444"), typeof(bool), null, CultureInfo.InvariantCulture));
    }

    /// <summary>
    /// Regression guard for the CopyStatus color wiring (Chunk 4 M1 had this
    /// backwards on first merge — TrueBrush was set to VtSuccessBrush while
    /// the bound value CopyStatusIsError is true on FAILURE). The
    /// IncidentStoryView wires TrueBrush=danger / FalseBrush=success; this
    /// test pins the contract that "is error = true" resolves to the danger
    /// brush through the converter, regardless of how the brushes are named
    /// at the call site.
    /// </summary>
    [Fact]
    public void Convert_IsErrorTrue_ResolvesDanger_NotSuccess()
    {
        // Mirror the IncidentStoryView wiring: TrueBrush=danger, FalseBrush=success.
        var danger = Brush("#ef4444");
        var success = Brush("#22c55e");
        var converter = new BoolToBrushConverter { TrueBrush = danger, FalseBrush = success };

        var onError = converter.Convert(true, typeof(IBrush), null, CultureInfo.InvariantCulture);
        var onSuccess = converter.Convert(false, typeof(IBrush), null, CultureInfo.InvariantCulture);

        Assert.Same(danger, onError);   // failure renders red
        Assert.Same(success, onSuccess); // success renders green
    }
}
