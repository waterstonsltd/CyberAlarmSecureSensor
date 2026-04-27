using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Common.Models.ParserConfiguration;
using CyberAlarm.SyslogRelay.Domain.Parsing.Errors;
using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Parsing.WatchGuard;

// Parses RFC3164 syslog messages forwarded directly from WatchGuard Firebox devices.
// Expected format (space-delimited, RemoveEmptyEntries):
//   <PRI>Mon DD HH:MM:SS Firebox <hostname> (<iso-timestamp>) firewall: msg_id="3000-XXXX" <action> <srcIface> <dstIface> <pktLen> <proto> <ttl> <tos> <srcIp> <dstIp> <srcPort> <dstPort> ...
// Indices:  0     1  2         3       4          5                6         7       8        9         10       11        12      13   14    15       16       17        18
internal sealed class WatchGuardFireboxParser : WatchGuardParserBase
{
    public const int ActionIndex = 8;
    public const int ProtocolIndex = 12;
    public const int SourceIpIndex = 15;
    public const int DestinationIpIndex = 16;
    public const int SourcePortIndex = 17;
    public const int DestinationPortIndex = 18;
    public const int MinimumFieldCount = 17;
    public const char FieldDelimiter = ' ';

    protected override Result<ParseResult> ParseLog(string log, WatchGuardParserConfig config)
    {
        var fields = log.Split(FieldDelimiter, StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length < MinimumFieldCount)
        {
            return new FormatError();
        }

        var action = ToAction(fields[ActionIndex], config);
        var sourceIp = fields[SourceIpIndex];
        var destinationIp = fields[DestinationIpIndex];
        var protocol = fields[ProtocolIndex].ToProtocol();
        var shouldExtractPorts = protocol is EventProtocol.Tcp or EventProtocol.Udp;
        var sourcePort = shouldExtractPorts && fields.Length > SourcePortIndex
            ? fields[SourcePortIndex].ToPort()
            : null;
        var destinationPort = shouldExtractPorts && fields.Length > DestinationPortIndex
            ? fields[DestinationPortIndex].ToPort()
            : null;

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
}
