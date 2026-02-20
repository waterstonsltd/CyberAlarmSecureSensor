namespace CyberAlarm.SyslogRelay.Common.Models;

public sealed record ParsingStageOutput(
    SyslogEvent SyslogEvent,
    PatternMatchResult? PatternMatchResult,
    ParseResult? ParseResult);
