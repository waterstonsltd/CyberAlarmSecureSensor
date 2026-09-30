namespace CyberAlarm.SyslogRelay.Common.Models.ParserConfiguration;

public sealed class LinuxNetfilterParserConfig : ParserConfig
{
    public required string ActionExtractRegex { get; init; }

    public int ActionCaptureGroup { get; init; } = 1;
}
