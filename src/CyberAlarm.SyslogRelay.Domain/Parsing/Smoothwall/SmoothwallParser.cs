using System.Text.RegularExpressions;
using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Common.Models.ParserConfiguration;
using CyberAlarm.SyslogRelay.Domain.Parsing.Errors;
using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Parsing.Smoothwall;

internal sealed partial class SmoothwallParser : KeyValueParserBase<ParserConfig>
{
    public const char PairDelimiter = ' ';
    public const char ValueDelimiter = '=';

    protected override Result<ParseResult> ParseLog(string log, ParserConfig config)
    {
        var actionMatch = ActionRegex().Match(log);
        if (actionMatch is null || !actionMatch.Success)
        {
            return new FormatError();
        }

        var keyValues = log.ParseKeyValues(PairDelimiter, ValueDelimiter);

        if (!keyValues.TryGetValueFrom(config.SourceIpKeys, out var sourceIp) ||
            (!keyValues.TryGetValueFrom(config.DestinationIpKeys, out var destinationIp) && !config.IsDestinationIpOptional) ||
            (!keyValues.TryGetValueFrom(config.SourcePortKeys, out var sourcePortValue) && !config.IsSourcePortOptional) ||
            (!keyValues.TryGetValueFrom(config.DestinationPortKeys, out var destinationPortValue) && !config.IsDestinationPortOptional) ||
            (!keyValues.TryGetValueFrom(config.ProtocolKeys, out var protocolValue) && !config.IsProtocolOptional))
        {
            return new UnparsableEventError();
        }

        return ToParseResult(
            config,
            sourceIp,
            destinationIp,
            sourcePortValue,
            destinationPortValue,
            protocolValue,
            actionMatch.Groups[1].Value,
            keyValues.ExtractDuration(config.DurationKeys, config.DurationIsSeconds),
            keyValues.ExtractBytes(config.TotalBytesKeys, config.SentBytesKeys, config.ReceivedBytesKeys));
    }

    [GeneratedRegex(@"kernel:\s+([A-Z]+)_.")]
    private static partial Regex ActionRegex();
}
