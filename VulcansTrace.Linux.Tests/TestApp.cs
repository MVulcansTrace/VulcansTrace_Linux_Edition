using Avalonia;
using Avalonia.Headless;
using Avalonia.Themes.Fluent;

[assembly: AvaloniaTestApplication(typeof(VulcansTrace.Linux.Tests.TestAppBuilder))]

namespace VulcansTrace.Linux.Tests;

/// <summary>
/// Configures the Avalonia headless application used by Avalonia headless XUnit tests.
/// </summary>
public class TestAppBuilder
{
    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<TestApp>()
            .UseHeadless(new AvaloniaHeadlessPlatformOptions())
            .WithInterFont();
}

/// <summary>
/// Minimal Avalonia application used to bootstrap the headless test session.
/// </summary>
public class TestApp : Application
{
    public override void Initialize()
    {
        Styles.Add(new FluentTheme());
        base.Initialize();
    }
}
