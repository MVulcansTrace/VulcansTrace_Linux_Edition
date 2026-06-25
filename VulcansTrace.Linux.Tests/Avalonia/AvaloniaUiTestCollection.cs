using Xunit;

namespace VulcansTrace.Linux.Tests.Avalonia;

[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class AvaloniaUiTestCollection
{
    public const string Name = "Avalonia UI tests";
}
