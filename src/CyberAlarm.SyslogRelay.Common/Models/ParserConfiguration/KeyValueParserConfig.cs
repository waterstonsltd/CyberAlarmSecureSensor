namespace CyberAlarm.SyslogRelay.Common.Models.ParserConfiguration;

public sealed partial class KeyValueParserConfig : ParserConfig
{
    public bool? UseRegex { get; init; }

    public string? RegexPatternOverride { get; init; }

    public string? PairDelimiter { get; init; }

    public string? ValueDelimiter { get; init; }
}
