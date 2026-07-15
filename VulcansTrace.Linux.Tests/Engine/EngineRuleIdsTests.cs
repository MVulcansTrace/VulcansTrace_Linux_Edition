using System.Reflection;
using VulcansTrace.Linux.Engine.Detectors;

namespace VulcansTrace.Linux.Tests.Engine;

public class EngineRuleIdsTests
{
    private static string[] GetAllRuleIds() =>
        typeof(EngineRuleIds)
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(f => f.IsLiteral && f.FieldType == typeof(string))
            .Select(f => (string)f.GetRawConstantValue()!)
            .ToArray();

    [Fact]
    public void AllEngineRuleIds_StartWithEngPrefix()
    {
        var ids = GetAllRuleIds();

        Assert.NotEmpty(ids);
        Assert.All(ids, id => Assert.StartsWith("ENG-", id));
    }

    [Fact]
    public void AllEngineRuleIds_AreUnique()
    {
        var ids = GetAllRuleIds();

        Assert.Equal(ids.Length, ids.Distinct().Count());
    }

    [Fact]
    public void AllEngineRuleIds_DoNotCollideWithAgentWildcardPatterns()
    {
        // Posture correlation matches agent ids with patterns like "PORT-*";
        // engine ids must never be captured by such a pattern.
        var ids = GetAllRuleIds();

        Assert.All(ids, id => Assert.False(id.StartsWith("PORT-", StringComparison.Ordinal)));
    }
}
