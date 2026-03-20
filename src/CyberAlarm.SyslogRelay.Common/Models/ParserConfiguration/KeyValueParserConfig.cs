using System.Text.RegularExpressions;

namespace CyberAlarm.SyslogRelay.Common.Models.ParserConfiguration;

public sealed partial class KeyValueParserConfig
{
    public string? RegexPattern { get; init; }

    public required string[] SourceIpKeys { get; init; }

    public required string[] DestinationIpKeys { get; init; }

    public bool IsDestinationIpOptional { get; init; }

    public required string[] SourcePortKeys { get; init; }

    public bool IsSourcePortOptional { get; init; }

    public required string[] DestinationPortKeys { get; init; }

    public bool IsDestinationPortOptional { get; init; }

    public required string[] ProtocolKeys { get; init; }

    public bool IsProtocolOptional { get; init; }

    public required string[] ActionKeys { get; init; }

    public bool IsActionOptional { get; init; }

    public required string[] AllowActionValues { get; init; }

    public required string[] DenyActionValues { get; init; }

    public string[] DropActionValues { get; init; } = [];

    public string[] CloseActionValues { get; init; } = [];

    public string[] ResetActionValues { get; init; } = [];

    public string[] TimeoutActionValues { get; init; } = [];

    public Regex Regex => string.IsNullOrEmpty(RegexPattern)
        ? DefaultRegex()
        : new(RegexPattern, RegexOptions.Compiled);

    [GeneratedRegex(@"(\w+)=(?:""([^""]*)""|(\S+))")]
    private static partial Regex DefaultRegex();
}
