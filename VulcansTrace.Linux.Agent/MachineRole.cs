namespace VulcansTrace.Linux.Agent;

/// <summary>
/// Defines the role of the machine being audited, used to tune rule strictness.
/// </summary>
public enum MachineRole
{
    /// <summary>A general-purpose workstation or laptop.</summary>
    Workstation,

    /// <summary>A production server or bastion host.</summary>
    Server,

    /// <summary>A lab or test box with relaxed security boundaries.</summary>
    LabBox,

    /// <summary>A network router or gateway appliance.</summary>
    Router,

    /// <summary>A development machine with extra services and ports.</summary>
    DevMachine
}
