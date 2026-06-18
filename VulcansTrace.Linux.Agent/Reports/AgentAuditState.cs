using VulcansTrace.Linux.Agent.Dialogue;

namespace VulcansTrace.Linux.Agent.Reports;

/// <summary>
/// Backward-compatible alias for <see cref="DialogueContext"/>.
/// Retained so existing services and tests continue to compile while the
/// agent gains conversation-aware capabilities.
/// </summary>
internal sealed class AgentAuditState : DialogueContext
{
}
