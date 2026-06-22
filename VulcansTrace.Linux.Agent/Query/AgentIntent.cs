namespace VulcansTrace.Linux.Agent.Query;

/// <summary>
/// Represents the structured intent derived from a user's natural language query.
/// </summary>
public enum AgentIntent
{
    /// <summary>Comprehensive system security audit.</summary>
    FullAudit,

    /// <summary>Focus on firewall configuration and rules.</summary>
    FirewallCheck,

    /// <summary>Focus on network interfaces, routes, and connections.</summary>
    NetworkCheck,

    /// <summary>Focus on running system services.</summary>
    ServiceCheck,

    /// <summary>Focus on open ports and listening services.</summary>
    PortCheck,

    /// <summary>Focus on SSH daemon configuration and hardening.</summary>
    SshCheck,

    /// <summary>Focus on sensitive file and directory permissions.</summary>
    FilePermissionCheck,

    /// <summary>Focus on filesystem audit findings (world-writable files, SUID/SGID, unowned files, sticky bit, /tmp hardening).</summary>
    FilesystemAuditCheck,

    /// <summary>Focus on kernel and system hardening parameters.</summary>
    KernelCheck,

    /// <summary>Focus on user accounts, passwords, and PAM configuration.</summary>
    UserAccountCheck,

    /// <summary>Focus on logging and auditing configuration (rsyslog, journald, auditd, logrotate, forwarding).</summary>
    LoggingAuditCheck,

    /// <summary>Focus on cron job entries, permissions, and suspicious scheduled tasks.</summary>
    CronJobCheck,

    /// <summary>Focus on package vulnerabilities and pending security updates.</summary>
    PackageVulnerabilityCheck,

    /// <summary>Focus on running containers and Docker/containerd security posture.</summary>
    ContainerCheck,

    /// <summary>Focus on Kubernetes pods and Pod Security Standard violations.</summary>
    KubernetesCheck,

    /// <summary>Focus on imported threat intelligence IOC correlations.</summary>
    ThreatIntelCheck,

    /// <summary>Focus on YARA rule matches for binaries, process executables, and cron scripts.</summary>
    YaraCheck,

    /// <summary>Focus on runtime process anomalies: memory injection, deleted binaries, LD_PRELOAD, suspicious parent-child.</summary>
    ProcessRuntimeCheck,

    /// <summary>Request explanation of a previous finding.</summary>
    ExplainFinding,

    /// <summary>Show the evidence chain / provenance for a finding.</summary>
    ShowEvidence,

    /// <summary>Show what changed since the last audit.</summary>
    ShowChanges,

    /// <summary>Explain why critical/high findings matter.</summary>
    ExplainCritical,

    /// <summary>Filter the last result to a specific category.</summary>
    FilterCategory,

    /// <summary>Prioritize findings into a remediation plan.</summary>
    PrioritizeRemediation,

    /// <summary>Interactively guide remediation for a specific finding.</summary>
    FixFinding,

    /// <summary>Report the outcome of a remediation step (success or failure with optional error text).</summary>
    ReportStepResult,

    /// <summary>List suppressed findings from the last result.</summary>
    ListSuppressed,

    /// <summary>Save the last audit as a known-good baseline.</summary>
    SetBaseline,

    /// <summary>Check whether the live config has drifted from the saved baseline.</summary>
    CheckDrift,

    /// <summary>Show the current baseline for an intent.</summary>
    ShowBaseline,

    /// <summary>Show the overall risk score and grade from the last audit.</summary>
    RiskScore,

    /// <summary>Start a guided remediation session for one or more findings.</summary>
    StartRemediation,

    /// <summary>Run verification on an active remediation session.</summary>
    VerifyRemediation,

    /// <summary>List persisted remediation sessions.</summary>
    ListRemediationSessions,

    /// <summary>Resume a previously created remediation session.</summary>
    ResumeRemediation,

    /// <summary>Add a note to a remediation session.</summary>
    AddSessionNote,

    /// <summary>Add a note to a specific remediation step.</summary>
    AddStepNote,

    /// <summary>Request help on available capabilities.</summary>
    Help,

    /// <summary>Start a diagnostic investigation into a recurring finding.</summary>
    InvestigateRecurrence,

    /// <summary>Answer a diagnostic question asked during a recurrence investigation.</summary>
    AnswerDiagnosticQuestion
}
