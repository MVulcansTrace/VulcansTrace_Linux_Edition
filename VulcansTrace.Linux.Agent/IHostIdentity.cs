using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent;

/// <summary>
/// Provides the identity of the machine being audited. Used to populate
/// <see cref="Finding.SourceHost"/> for agent-produced findings (rule findings, baseline
/// drift, change detection, rehydrated snapshots) instead of a hardcoded placeholder, so
/// exports, grouping, and fingerprints reflect the actual host.
/// </summary>
public interface IHostIdentity
{
    /// <summary>Short machine name (e.g. <see cref="Environment.MachineName"/>).</summary>
    string HostName { get; }

    /// <summary>
    /// Value recorded as <see cref="Finding.SourceHost"/> for findings produced on this host.
    /// Falls back to <see cref="HostName"/> when no explicit address is known.
    /// </summary>
    string SourceHost { get; }
}

/// <summary>
/// Default <see cref="IHostIdentity"/> backed by <see cref="Environment.MachineName"/>.
/// The name is resolved once at construction and the instance is safe to share as a singleton.
/// Falls back to "localhost" when the machine name cannot be resolved (e.g. restricted
/// sandbox environments, where <see cref="Environment.MachineName"/> may throw or be empty).
/// </summary>
public sealed class MachineHostIdentity : IHostIdentity
{
    /// <summary>Creates an identity resolved from <see cref="Environment.MachineName"/>.</summary>
    public MachineHostIdentity()
    {
        HostName = ResolveMachineName();
        SourceHost = HostName;
    }

    /// <inheritdoc/>
    public string HostName { get; }

    /// <inheritdoc/>
    public string SourceHost { get; }

    private static string ResolveMachineName()
    {
        try
        {
            var name = Environment.MachineName;
            return string.IsNullOrWhiteSpace(name) ? "localhost" : name;
        }
        catch (InvalidOperationException)
        {
            return "localhost";
        }
    }
}
