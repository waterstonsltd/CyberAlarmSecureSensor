using System.Globalization;
using System.Text.RegularExpressions;
using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Parsing.Errors;
using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Parsing.Barracuda;

// Parses Barracuda CloudGen Firewall native (positional pipe-delimited) syslog messages.
//
// Syslog format (RFC 3164):
//   <PRI>Mon DD HH:MM:SS HOSTNAME HOSTNAME/box_Firewall_Activity:  SEVERITY     HOSTNAME ACTION: PAYLOAD
//
// Payload fields (0-indexed, pipe-delimited):
//   [0] = connection type  (FWD, IFWD, LOUT, LRD, etc.)
//   [1] = protocol         (TCP, UDP, ICMP)
//   [2] = source interface
//   [3] = source IP
//   [4] = source port      (TCP/UDP only; ICMP identifier otherwise — not extracted as port)
//   [5] = source MAC
//   [6] = destination IP
//   [7] = destination port (TCP/UDP only)
//   [8] = destination service name
//   [9] = destination interface
//  [10] = firewall rule name
//  [11] = error code (0 for Allow, e.g. 4002 for Block)
//  [12] = source NAT IP
//  [13] = destination NAT IP
//  [14] = session duration in seconds
//
// Action semantics:
//   Allow  → Allow (traffic forwarded)
//   Block  → Drop  (silent discard — no TCP RST sent)
//   Detect → Allow (application identification event; traffic was forwarded)
internal sealed partial class BarracudaCgfParser : IParser
{
    private const int MinFields = 15;

    public Result Initialise(object? config) => Result.Ok();

    public Result<ParseResult> Parse(string log)
    {
        ArgumentException.ThrowIfNullOrEmpty(log);

        var match = LogPattern().Match(log);
        if (!match.Success)
        {
            return new FormatError();
        }

        var action = BarracudaCgfHelper.ResolveActivityAction(match.Groups["action"].Value);
        var fields = match.Groups["payload"].Value.Split('|');

        if (fields.Length < MinFields)
        {
            return new FormatError();
        }

        var protocol = BarracudaCgfHelper.ResolveProtocol(fields[1]);
        var srcIp = fields[3];
        var dstIp = fields[6];

        int? srcPort = null;
        int? dstPort = null;

        if (BarracudaCgfHelper.HasPorts(protocol))
        {
            srcPort = fields[4].ToPort();
            dstPort = fields[7].ToPort();
        }

        TimeSpan? duration = null;

        if (long.TryParse(fields[14], NumberStyles.Integer, CultureInfo.InvariantCulture, out var secs))
        {
            duration = TimeSpan.FromSeconds(secs);
        }

        return new ParseResult(srcIp, dstIp, srcPort, dstPort, protocol, action, duration);
    }

    [GeneratedRegex(
        @"^<\d+>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+/box_Firewall_Activity:\s+\w+\s+\S+\s+(?<action>Allow|Block|Detect):\s+(?<payload>.+)$",
        RegexOptions.None,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex LogPattern();
}
