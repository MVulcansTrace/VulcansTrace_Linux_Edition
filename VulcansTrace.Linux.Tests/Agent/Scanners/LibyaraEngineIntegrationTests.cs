using VulcansTrace.Linux.Agent.Scanners;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent.Scanners;

public class LibyaraEngineIntegrationTests
{
    [SkippableFact]
    public void CompileRules_ValidRule_CompilesSuccessfully()
    {
        using var engine = new LibyaraEngine();
        Skip.IfNot(engine.IsAvailable, "libyara is not installed or could not be loaded.");

        const string rule = "rule test_rule { strings: $a = \"hello\" condition: $a }";
        var errors = engine.CompileRules(rule);

        Assert.Empty(errors);
    }

    [SkippableFact]
    public void ScanFile_MatchingRule_ReturnsMatch()
    {
        using var engine = new LibyaraEngine();
        Skip.IfNot(engine.IsAvailable, "libyara is not installed or could not be loaded.");

        const string rule = "rule test_rule { strings: $a = \"UNIQUE_TEST_STRING_42\" condition: $a }";
        var compileErrors = engine.CompileRules(rule);
        Assert.Empty(compileErrors);

        var path = Path.Combine(Path.GetTempPath(), $"yara-int-test-{Guid.NewGuid()}.txt");
        File.WriteAllText(path, "prefix UNIQUE_TEST_STRING_42 suffix");
        try
        {
            var matches = engine.ScanFile(path, timeoutSeconds: 10);

            var match = Assert.Single(matches);
            Assert.Equal("test_rule", match.RuleIdentifier);
        }
        finally
        {
            try { File.Delete(path); } catch { }
        }
    }

    [SkippableFact]
    public void ScanFile_NonMatchingRule_ReturnsNoMatches()
    {
        using var engine = new LibyaraEngine();
        Skip.IfNot(engine.IsAvailable, "libyara is not installed or could not be loaded.");

        const string rule = "rule test_rule { strings: $a = \"NOT_PRESENT\" condition: $a }";
        var compileErrors = engine.CompileRules(rule);
        Assert.Empty(compileErrors);

        var path = Path.Combine(Path.GetTempPath(), $"yara-int-test-{Guid.NewGuid()}.txt");
        File.WriteAllText(path, "some other content");
        try
        {
            var matches = engine.ScanFile(path, timeoutSeconds: 10);
            Assert.Empty(matches);
        }
        finally
        {
            try { File.Delete(path); } catch { }
        }
    }
}
