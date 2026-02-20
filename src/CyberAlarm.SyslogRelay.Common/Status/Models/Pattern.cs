namespace CyberAlarm.SyslogRelay.Common.Status.Models;

public sealed class Pattern
{
    public string Name { get; init; } = string.Empty;

    public int Priority { get; init; }

    public string ParserClass { get; init; } = string.Empty;

    public List<PatternRule> Rules { get; init; } = [];
}
