namespace CyberAlarm.SyslogRelay.Common.Models;

public sealed record PatternMatchResult(string PatternName, IParser Parser);
