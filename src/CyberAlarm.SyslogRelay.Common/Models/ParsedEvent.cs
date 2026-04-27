using System.Text.Json.Serialization;

namespace CyberAlarm.SyslogRelay.Common.Models;

public sealed record ParsedEvent(
    DateTime Timestamp,
    EventSource EventSource,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? RawData,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? PatternName,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] ParseResult? ParseResult,
    ValidationStatus ValidationStatus);
