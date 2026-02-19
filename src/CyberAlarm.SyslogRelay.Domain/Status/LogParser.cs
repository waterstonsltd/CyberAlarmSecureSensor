namespace CyberAlarm.SyslogRelay.Domain.Status;

public sealed class LogParser
{
    public required string Name { get; init; }

    public required string Version { get; init; }

    public required bool Enabled { get; init; }

    public int Priority { get; init; }

    public string[] Patterns { get; init; } = [];

    public object Configuration { get; init; } = new();
}
