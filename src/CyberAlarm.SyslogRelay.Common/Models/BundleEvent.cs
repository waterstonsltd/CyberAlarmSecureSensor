using System.Text.Json.Serialization;

namespace CyberAlarm.SyslogRelay.Common.Models;

public sealed record BundleEvent(
    DateTime Timestamp,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? RawData,
    string? PatternName,
    ParseResult? ParseResult);
