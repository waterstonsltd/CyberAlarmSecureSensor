namespace CyberAlarm.SyslogRelay.Common.Models;

public sealed record ParsedEvent(
    DateTime Timestamp,
    EventSource EventSource,
    string? RawData,
    ParsingMetadata? ParsingMetadata,
    ParsedFirewallEvent? ParsedFirewallEvent);
