namespace CyberAlarm.SyslogRelay.Common.Models.ParserConfiguration;

public sealed class WatchGuardParserConfig
{
    public string[] AllowActionValues { get; init; } = [];

    public string[] DenyActionValues { get; init; } = [];

    public string[] DurationKeys { get; init; } = [];

    public bool DurationIsSeconds { get; init; }

    public string[] SentBytesKeys { get; init; } = [];

    public string[] ReceivedBytesKeys { get; init; } = [];
}
