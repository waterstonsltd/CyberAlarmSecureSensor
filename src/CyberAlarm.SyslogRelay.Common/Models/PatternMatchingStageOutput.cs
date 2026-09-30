namespace CyberAlarm.SyslogRelay.Common.Models;

public sealed record PatternMatchingStageOutput(
    SyslogEvent SyslogEvent,
    PatternMatchResult? PatternMatchResult);
