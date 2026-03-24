using System.Text.RegularExpressions;

namespace CyberAlarm.SyslogRelay.Common.Models.ParserConfiguration;

public sealed partial class KeyValueParserConfig
{
    // Cached on first access — constructing a Regex (especially with RegexOptions.Compiled)
    // is expensive and must not happen on every Parse() call.
    private Regex? _regex;

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

    public string[] DurationKeys { get; init; } = [];

    /// <summary>
    /// Gets a value indicating whether <see langword="true"/>, values matched by <see cref="DurationKeys"/> are treated as
    /// integer seconds rather than a <see cref="TimeSpan"/>-parseable string.
    /// </summary>
    public bool DurationIsSeconds { get; init; }

    public string[] TotalBytesKeys { get; init; } = [];

    public string[] SentBytesKeys { get; init; } = [];

    public string[] ReceivedBytesKeys { get; init; } = [];

    public Regex Regex => _regex ??= string.IsNullOrEmpty(RegexPattern)
        ? DefaultRegex()
        : new(RegexPattern, RegexOptions.Compiled, matchTimeout: TimeSpan.FromSeconds(1));

    [GeneratedRegex(@"(\w+)=(?:""([^""]*)""|(\S+))")]
    private static partial Regex DefaultRegex();
}
