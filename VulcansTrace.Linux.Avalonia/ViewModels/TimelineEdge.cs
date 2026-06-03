using System;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// Screen-space coordinates and metadata for a correlation edge drawn on the timeline canvas.
/// </summary>
public sealed class TimelineEdge
{
    /// <summary>The <see cref="Core.Finding.Id"/> of the origin finding.</summary>
    public Guid FromFindingId { get; set; }

    /// <summary>The <see cref="Core.Finding.Id"/> of the destination finding.</summary>
    public Guid ToFindingId { get; set; }

    /// <summary>Horizontal start of the origin bar (0-1 normalized).</summary>
    public double FromStartPosition { get; set; }

    /// <summary>Horizontal end of the origin bar (0-1 normalized).</summary>
    public double FromEndPosition { get; set; }

    /// <summary>Vertical row position of the origin bar (pixels).</summary>
    public double FromTopPosition { get; set; }

    /// <summary>Horizontal start of the destination bar (0-1 normalized).</summary>
    public double ToStartPosition { get; set; }

    /// <summary>Horizontal end of the destination bar (0-1 normalized).</summary>
    public double ToEndPosition { get; set; }

    /// <summary>Vertical row position of the destination bar (pixels).</summary>
    public double ToTopPosition { get; set; }

    /// <summary>The nature of the correlation.</summary>
    public CorrelationType CorrelationType { get; set; }

    /// <summary>Human-readable explanation shown in the edge tooltip.</summary>
    public string Narrative { get; set; } = string.Empty;
}
