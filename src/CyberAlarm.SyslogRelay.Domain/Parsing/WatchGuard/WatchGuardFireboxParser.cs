using System.Text.RegularExpressions;
using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Common.Models.ParserConfiguration;
using CyberAlarm.SyslogRelay.Domain.Parsing.Errors;
using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Parsing.WatchGuard;

// Parses RFC3164 syslog messages forwarded directly from WatchGuard Firebox devices.
// Handles multiple message formats:
//   - Standard (3000-0148): <action> <srcIface> <dstIface> <pktLen> <proto> <ttl> <tos> <srcIp> <dstIp> <srcPort> <dstPort> ...
//   - Short (3000-0151): <action> <srcIface> <dstIface> <proto> <srcIp> <dstIp> <srcPort> <dstPort> ...
//   - With fqdn prefix: fqdn_dst_match="x" <action> ...
//   - ICMP: <action> <srcIface> <dstIface> icmp <srcIp> <dstIp> <icmpType> ...
//   - Multi-word interface names: <action> <word> <word> ... <proto> <srcIp> <dstIp> ...
internal sealed partial class WatchGuardFireboxParser : WatchGuardParserBase
{
    private const string RegexPattern =
        @"(?<action>Allow|Deny)\s+" +
        @"(?:\S+\s+)*?" +
        @"(?:\d+\s+)?" +
        @"(?<protocol>tcp|udp|icmp)\s+" +
        @"(?:\d+\s+\d+\s+)?" +
        @"(?<srcIp>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+" +
        @"(?<dstIp>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})" +
        @"(?:\s+(?<srcPort>\d+)\s+(?<dstPort>\d+))?";

    protected override Result<ParseResult> ParseLog(string log, WatchGuardParserConfig config)
    {
        var match = FireboxMessageRegex().Match(log);
        if (!match.Success)
        {
            return new FormatError();
        }

        var action = ToAction(match.From("action"), config);
        var protocol = match.From("protocol").ToProtocol();
        var sourceIp = match.From("srcIp");
        var destinationIp = match.From("dstIp");

        // Only extract ports for TCP/UDP protocols
        int? sourcePort = null;
        int? destinationPort = null;
        if (protocol is EventProtocol.Tcp or EventProtocol.Udp)
        {
            sourcePort = match.NumberFrom("srcPort");
            destinationPort = match.NumberFrom("dstPort");
        }

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

    [GeneratedRegex(RegexPattern, RegexOptions.IgnoreCase, matchTimeoutMilliseconds: 1000)]
    private static partial Regex FireboxMessageRegex();
}
