using System.Text.Json;
using System.Text.Json.Serialization;

namespace VulcansTrace.Linux.Agent.Sessions;

/// <summary>
/// Serializes DateTime as ISO 8601 and deserializes with DateTimeKind.Utc.
/// Prevents System.Text.Json from defaulting to Unspecified kind on round-trip.
/// </summary>
public sealed class UtcDateTimeJsonConverter : JsonConverter<DateTime>
{
    public override DateTime Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var value = reader.GetDateTime();
        return DateTime.SpecifyKind(value, DateTimeKind.Utc);
    }

    public override void Write(Utf8JsonWriter writer, DateTime value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(value.ToUniversalTime());
    }
}
