namespace CyberAlarm.SyslogRelay.Common.Models;

public sealed record ValidationStageOutput(
    SyslogEvent SyslogEvent,
    PatternMatchResult? PatternMatchResult,
    ParseResult? ParseResult,
    ValidationResult ValidationResult);
