using System.Text.RegularExpressions;
using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Parsing.Errors;
using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Parsing.Barracuda;

// Parses Barracuda CloudGen Firewall threat/IPS syslog messages from /box_Firewall_threat.
//
// Example:
//   <12>Feb 12 15:10:41 T100 T100/box_Firewall_threat:  Warning  T100 firewall: [Request] Allow:   IPS ALLIP(0) 192.168.0.22 -> 0.0.0.0:0 |[ID: 5000002 TCPIP Port or IP Address Scan]||3|Probing
//
// Extracts source IP, destination IP/port, and action.
// Protocol is not present in the threat log format — EventProtocol.Unknown is used.
// Destination IP 0.0.0.0 (any/wildcard) and port 0 are normalised to null.
//
// Action semantics:
//   Allow → Allow (IPS inspected and permitted the traffic)
//   Block → Deny  (IPS blocked the traffic)
internal sealed partial class BarracudaCgfThreatParser : IParser
{
    public Result Initialise(object? config) => Result.Ok();

    public Result<ParseResult> Parse(string log)
    {
        ArgumentException.ThrowIfNullOrEmpty(log);
        return ParseThreatLog(log);
    }

    private static Result<ParseResult> ParseThreatLog(string log)
    {
        var match = LogPattern().Match(log);
        if (!match.Success)
        {
            return new FormatError();
        }

        var action = ResolveAction(match.Groups["action"].Value);
        var srcIp = match.Groups["src_ip"].Value;

        var rawDstIp = match.Groups["dst_ip"].Value;
        string? dstIp = rawDstIp == "0.0.0.0" ? null : rawDstIp;

        int? dstPort = match.NumberFrom("dst_port") is int p and > 0 ? p : null;

        return new ParseResult(srcIp, dstIp, null, dstPort, EventProtocol.Unknown, action);
    }

    private static EventAction ResolveAction(string action) =>
        action switch
        {
            "Allow" => EventAction.Allow,
            "Block" => EventAction.Deny,
            _ => EventAction.Unknown,
        };

    [GeneratedRegex(
        @"\[Request\]\s+(?<action>Allow|Block):\s+.*?(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})\s+->\s+(?<dst_ip>\d{1,3}(?:\.\d{1,3}){3}):(?<dst_port>\d+)",
        RegexOptions.None,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex LogPattern();
}
