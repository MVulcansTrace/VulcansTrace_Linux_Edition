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

    public void SetLastResult(AgentResult result)
    {
        LastResult = result ?? throw new ArgumentNullException(nameof(result));
        IsExportableAudit = IsAuditIntent(result.Intent);
        NotifyResultStateChanged();
    }

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
