namespace CyberAlarm.SyslogRelay.Common.Models;

public sealed record ParsedEvent(
    DateTime Timestamp,
    EventSource EventSource,
    string? RawData,
    string? PatternName,
    ParseResult? ParseResult);
