using System.Text.Json;

namespace CyberAlarm.SyslogRelay.Domain;

internal static class SerializationOptions
{
    public static readonly JsonSerializerOptions Default = new()
    {
        AllowTrailingCommas = true,
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
    };
}
