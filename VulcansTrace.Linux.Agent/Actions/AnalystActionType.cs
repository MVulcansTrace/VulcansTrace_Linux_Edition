namespace VulcansTrace.Linux.Agent.Actions;

/// <summary>
/// Well-known action types recorded in the analyst action audit log.
/// </summary>
public static class AnalystActionType
{
    public const string AuditRan = "AuditRan";
    public const string AuditDiffRan = "AuditDiffRan";
    public const string FindingVerified = "FindingVerified";
    public const string EvidenceExported = "EvidenceExported";
    public const string RemediationPlanExported = "RemediationPlanExported";
    public const string SessionReportExported = "SessionReportExported";
    public const string ThreatIntelExported = "ThreatIntelExported";
    public const string ThreatIntelImported = "ThreatIntelImported";
    public const string ThreatIntelCleared = "ThreatIntelCleared";
    public const string ThreatIntelRemoved = "ThreatIntelRemoved";
    public const string SuppressionAdded = "SuppressionAdded";
    public const string BaselineSet = "BaselineSet";
    public const string DriftChecked = "DriftChecked";
    public const string CountermeasureDeployed = "CountermeasureDeployed";
    public const string BatchAutoFixRan = "BatchAutoFixRan";
    public const string ScheduleAdded = "ScheduleAdded";
    public const string ScheduleEdited = "ScheduleEdited";
    public const string ScheduleDeleted = "ScheduleDeleted";
    public const string ScheduleEnabled = "ScheduleEnabled";
    public const string ScheduleDisabled = "ScheduleDisabled";
    public const string NotificationSettingsChanged = "NotificationSettingsChanged";
    public const string RulePolicyEdited = "RulePolicyEdited";
}
