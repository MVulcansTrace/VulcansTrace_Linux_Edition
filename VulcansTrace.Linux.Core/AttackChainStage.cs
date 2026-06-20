namespace VulcansTrace.Linux.Core;

/// <summary>
/// A kill-chain stage used to order findings into an attack narrative.
/// </summary>
public enum AttackChainStage
{
    /// <summary>Reconnaissance against the target.</summary>
    Reconnaissance,

    /// <summary>Initial access to the target.</summary>
    InitialAccess,

    /// <summary>Credential access attempts.</summary>
    CredentialAccess,

    /// <summary>Execution on the target.</summary>
    Execution,

    /// <summary>Lateral movement across systems.</summary>
    LateralMovement,

    /// <summary>Data exfiltration.</summary>
    Exfiltration
}
