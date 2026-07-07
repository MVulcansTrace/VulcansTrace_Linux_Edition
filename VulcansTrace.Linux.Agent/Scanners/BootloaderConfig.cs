using System.Collections.Generic;

namespace VulcansTrace.Linux.Agent.Scanners;

/// <summary>Boot loader configuration (GRUB defaults, kernel command line, Secure Boot).</summary>
public sealed record BootloaderConfig
{
    /// <summary>Whether the boot loader data could be read.</summary>
    public bool ConfigReadable { get; init; }

    /// <summary>Whether /etc/default/grub exists.</summary>
    public bool GrubFileExists { get; init; }

    /// <summary>Parsed GRUB variables from /etc/default/grub.</summary>
    public IReadOnlyDictionary<string, string> GrubVariables { get; init; } = new Dictionary<string, string>();

    /// <summary>Whether GRUB password or superuser configuration was found.</summary>
    public bool GrubPasswordConfigured { get; init; }

    /// <summary>Current kernel command line read from /proc/cmdline.</summary>
    public string KernelCmdline { get; init; } = string.Empty;

    /// <summary>Secure Boot state, or null if UEFI/Secure Boot is unavailable.</summary>
    public bool? SecureBootEnabled { get; init; }

    /// <summary>Warning or detail message if reading failed.</summary>
    public string? ReadWarning { get; init; }
}
