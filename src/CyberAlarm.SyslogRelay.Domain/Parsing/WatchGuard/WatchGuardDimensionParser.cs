using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Common.Models.ParserConfiguration;
using CyberAlarm.SyslogRelay.Domain.Parsing.Errors;
using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Parsing.WatchGuard;

internal sealed class WatchGuardDimensionParser : WatchGuardParserBase
{
    public const int HostnameIndex = 2;
    public const int ActionIndex = 2;
    public const int SourceIpIndex = 3;
    public const int DestinationIpIndex = 4;
    public const int ServiceProtocolIndex = 5;
    public const int SourcePortIndex = 6;
    public const int DestinationPortIndex = 7;
    public const int MinimumFieldCount = 8;
    public const char FieldDelimiter = ' ';
    public const char ServiceProtocolDelimiter = '/';
    public const char PairDelimiter = ' ';
    public const char ValueDelimiter = '=';

    protected override Result<ParseResult> ParseLog(string log, WatchGuardParserConfig config)
    {
        var fields = log.Split(FieldDelimiter, StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length < MinimumFieldCount)
        {
            return new FormatError();
        }

        var offset = 0;

        if (config.AllowActionValues.All(x => x != fields[HostnameIndex]) &&
            config.DenyActionValues.All(x => x != fields[HostnameIndex]))
        {
            // This field is a hostname so shift all subsequent fields by 1
            offset += 1;
        }

        if (fields.Length < (MinimumFieldCount + offset))
        {
            return new FormatError();
        }

        var action = ToAction(fields[ActionIndex + offset], config);
        var sourceIp = fields[SourceIpIndex + offset];
        var destinationIp = fields[DestinationIpIndex + offset];
        var protocol = ToProtocol(fields[ServiceProtocolIndex + offset]);
        var shouldExtractPorts = protocol is EventProtocol.Tcp or EventProtocol.Udp;
        var sourcePort = shouldExtractPorts ? fields[SourcePortIndex + offset].ToPort() : null;
        var destinationPort = shouldExtractPorts ? fields[DestinationPortIndex + offset].ToPort() : null;

        TimeSpan? duration = default;
        long? bytes = default;

        var keyValues = ParseKeyValuesFromRegex(log);
        if (keyValues != null)
        {
            duration = keyValues.ExtractDuration(config.DurationKeys, config.DurationIsSeconds);
            bytes = keyValues.ExtractBytes([], config.SentBytesKeys, config.ReceivedBytesKeys);
        }

        return new ParseResult(
            sourceIp,
            destinationIp,
            sourcePort,
            destinationPort,
            protocol,
            action,
            duration,
            bytes);
    }

    private static EventProtocol ToProtocol(string? serviceProtocol)
    {
        var values = serviceProtocol?.Split(ServiceProtocolDelimiter);
        return values is not null && values.Length == 2
            ? values[1].ToProtocol()
            : EventProtocol.Unknown;
    }
}
