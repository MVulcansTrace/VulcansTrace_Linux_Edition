using System;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

internal sealed class AgentResultStateCoordinator
{
    private readonly AgentHistoryCoordinator _historyCoordinator;
    private readonly Action<string> _notifyPropertyChanged;
    private readonly Action _refreshResultCommands;
    private readonly Action<AgentResult> _publishAuditCompleted;

    public AgentResultStateCoordinator(
        AgentHistoryCoordinator historyCoordinator,
        Action<string> notifyPropertyChanged,
        Action refreshResultCommands,
        Action<AgentResult> publishAuditCompleted)
    {
        _historyCoordinator = historyCoordinator ?? throw new ArgumentNullException(nameof(historyCoordinator));
        _notifyPropertyChanged = notifyPropertyChanged ?? throw new ArgumentNullException(nameof(notifyPropertyChanged));
        _refreshResultCommands = refreshResultCommands ?? throw new ArgumentNullException(nameof(refreshResultCommands));
        _publishAuditCompleted = publishAuditCompleted ?? throw new ArgumentNullException(nameof(publishAuditCompleted));
    }

    public AgentResult? LastResult { get; private set; }
    public bool HasCompletedAudit { get; private set; }
    public AgentIntent LastAuditIntent { get; private set; } = AgentIntent.FullAudit;
    public bool IsExportableAudit { get; private set; }

    public void Reset()
    {
        LastResult = null;
        IsExportableAudit = false;
        HasCompletedAudit = false;
        LastAuditIntent = AgentIntent.FullAudit;
        NotifyResultStateChanged();
    }

    public void SetLastResult(AgentResult result, AgentResult? sourceAudit = null)
    {
        ArgumentNullException.ThrowIfNull(result);

        // Cached renderings (short verdict, findings recap) present existing audit data in a
        // different shape; they must not replace the last real audit. Otherwise export/batch-fix
        // enablement and SelectedFindingProvider would flip off despite the audit still being the
        // active context. Command state is still refreshed so dependents re-evaluate.
        if (IsCachedRendering(result.Intent))
        {
            // A SecurityAgent may have rehydrated its audit from persistent memory while this UI
            // coordinator is still empty (startup or role/agent swap). Seed from that real audit
            // so export, batch-fix, and selected-finding state become available again.
            if (LastResult == null && sourceAudit != null && IsAuditIntent(sourceAudit.Intent))
            {
                LastResult = sourceAudit;
                IsExportableAudit = true;
                HasCompletedAudit = true;
                LastAuditIntent = sourceAudit.Intent;
            }

            NotifyResultStateChanged();
            return;
        }

        LastResult = result;
        IsExportableAudit = IsAuditIntent(result.Intent);
        NotifyResultStateChanged();
    }

    /// <summary>
    /// Results that re-present the most recent audit in a different shape (a one-line verdict or
    /// a findings recap) rather than producing a new audit. These are render-only with respect to
    /// the view-model's "last result" state.
    /// </summary>
    private static bool IsCachedRendering(AgentIntent intent) =>
        intent is AgentIntent.ShortVerdict or AgentIntent.ShowFindings;

    public void PublishAuditCompleted(AgentResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        _publishAuditCompleted(result);
        HasCompletedAudit = true;
        LastAuditIntent = result.Intent;
        IsExportableAudit = true;
        NotifyResultStateChanged();
        _historyCoordinator.AppendHistoryEntry(result);
    }

    private void NotifyResultStateChanged()
    {
        _notifyPropertyChanged(nameof(AgentViewModel.LastResult));
        _notifyPropertyChanged(nameof(AgentViewModel.CanExportAudit));
        _refreshResultCommands();
    }

    public static bool IsAuditIntent(AgentIntent intent) =>
        intent is AgentIntent.FullAudit
            or AgentIntent.FirewallCheck
            or AgentIntent.PortCheck
            or AgentIntent.ServiceCheck
            or AgentIntent.NetworkCheck
            or AgentIntent.SshCheck
            or AgentIntent.FilePermissionCheck
            or AgentIntent.FilesystemAuditCheck
            or AgentIntent.KernelCheck
            or AgentIntent.UserAccountCheck
            or AgentIntent.LoggingAuditCheck
            or AgentIntent.CronJobCheck
            or AgentIntent.PackageVulnerabilityCheck
            or AgentIntent.ContainerCheck
            or AgentIntent.KubernetesCheck
            or AgentIntent.ThreatIntelCheck
            or AgentIntent.YaraCheck
            or AgentIntent.ProcessRuntimeCheck;
}
