namespace VulcansTrace.Linux.Agent.Extensions;

/// <summary>
/// General-purpose string extensions used across the agent.
/// </summary>
public static class StringExtensions
{
    /// <summary>
    /// Truncates a string to a maximum total length, appending an ellipsis when truncated.
    /// </summary>
    /// <param name="value">The string to truncate.</param>
    /// <param name="maxLength">The maximum total length of the returned string.</param>
    /// <returns>
    /// The original string if it is shorter than <paramref name="maxLength"/>;
    /// otherwise a truncated string ending with "..." whose total length is at most
    /// <paramref name="maxLength"/>.
    /// </returns>
    public static string TruncateWithEllipsis(this string value, int maxLength)
    {
        ArgumentNullException.ThrowIfNull(value);

        if (value.Length <= maxLength)
            return value;

        if (maxLength <= 3)
            return value.Substring(0, maxLength);

        return value.Substring(0, maxLength - 3) + "...";
    }
}
