using System.Linq;
using System.Threading.Tasks;
using Avalonia.Media;
using VulcansTrace.Linux.Avalonia.Converters;
using Xunit;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class ThemeBrushTests
{
    [AvaloniaFact]
    public void Get_SameFallbackColor_ReturnsSameBrushInstance()
    {
        ThemeBrush.ClearFallbackCache();

        var brush1 = ThemeBrush.Get("MissingKey", Color.Parse("#ff0000"));
        var brush2 = ThemeBrush.Get("MissingKey", Color.Parse("#ff0000"));

        Assert.Same(brush1, brush2);
    }

    [AvaloniaFact]
    public void Get_DifferentFallbackColors_ReturnDifferentBrushes()
    {
        ThemeBrush.ClearFallbackCache();

        var brush1 = ThemeBrush.Get("MissingKey1", Color.Parse("#ff0000"));
        var brush2 = ThemeBrush.Get("MissingKey2", Color.Parse("#00ff00"));

        Assert.NotSame(brush1, brush2);
    }

    [AvaloniaFact]
    public void ClearFallbackCache_RemovesCachedEntries()
    {
        ThemeBrush.ClearFallbackCache();

        var brush1 = ThemeBrush.Get("MissingKey", Color.Parse("#ff0000"));
        ThemeBrush.ClearFallbackCache();
        var brush2 = ThemeBrush.Get("MissingKey", Color.Parse("#ff0000"));

        Assert.NotSame(brush1, brush2);
    }

    [AvaloniaFact]
    public void Get_ConcurrentReads_DoNotThrow()
    {
        ThemeBrush.ClearFallbackCache();

        var tasks = Enumerable.Range(0, 100)
            .Select(_ => Task.Run(() => ThemeBrush.Get("MissingKey", Color.Parse("#ff0000"))))
            .ToArray();

        var exception = Record.Exception(() => Task.WaitAll(tasks));
        Assert.Null(exception);
    }
}
