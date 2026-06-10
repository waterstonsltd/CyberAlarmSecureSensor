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

    // Source-generated options for the high-volume NDJSON path (ParsedEvent / BundleEvent).
    // Other types continue to use Default with reflection.
    public static readonly JsonSerializerOptions Ndjson = new()
    {
        AllowTrailingCommas = true,
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        TypeInfoResolver = RelayJsonContext.Default,
    };

    public static readonly JsonSerializerOptions ParserConfig = Default;
}
