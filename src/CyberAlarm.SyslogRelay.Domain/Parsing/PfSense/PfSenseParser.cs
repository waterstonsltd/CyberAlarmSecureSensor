using System.Text.RegularExpressions;
using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Parsing.Errors;
using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Parsing.PfSense;

// Parses pfSense/OPNsense firewall log messages produced by pf(4) filterlog.
// The syslog message payload is a comma-separated value (CSV) string with positional fields.
//
// Supported syslog header formats:
//   RFC 3164: <PRI>Mon DD HH:MM:SS [hostname] filterlog[pid]: CSV
//   RFC 5424: <PRI>1 ISO-TS hostname filterlog PID - - CSV
//
// IPv4 CSV field layout (field[8] == "4"):
//   [6]=action  [16]=proto  [18]=src_ip  [19]=dst_ip
//   TCP/UDP: [20]=src_port  [21]=dst_port
//
// IPv6 CSV field layout (field[8] == "6"):
//   [6]=action  [12]=proto  [15]=src_ip  [16]=dst_ip
//   TCP/UDP: [17]=src_port  [18]=dst_port
//
// Action values: pass → Allow, block/reject → Deny.
internal sealed partial class PfSenseParser : IParser
{
    private const int MinFieldsForIpv4 = 20;
    private const int MinFieldsForIpv6 = 17;

    public Result Initialise(object? config) => Result.Ok();

    public Result<ParseResult> Parse(string log)
    {
        ArgumentException.ThrowIfNullOrEmpty(log);

        var match = LogPattern().Match(log);
        if (!match.Success)
        {
            return new FormatError();
        }

        var fields = match.Groups["csv"].Value.Split(',');

        if (fields.Length < 9)
        {
            return new FormatError();
        }

        var action = ResolveAction(fields[6]);
        var ipVersion = fields[8];

        if (ipVersion == "4")
        {
            return ParseIpv4(fields, action);
        }

        if (ipVersion == "6")
        {
            return ParseIpv6(fields, action);
        }

        return new FormatError();
    }

    private static Result<ParseResult> ParseIpv4(string[] fields, EventAction action)
    {
        if (fields.Length < MinFieldsForIpv4)
        {
            return new FormatError();
        }

        var protocol = fields[16].ToProtocol();
        var srcIp = fields[18];
        var dstIp = fields[19];
        int? srcPort = null;
        int? dstPort = null;

        if (fields.Length > 21 && HasPorts(protocol))
        {
            srcPort = fields[20].ToPort();
            dstPort = fields[21].ToPort();
        }

        return new ParseResult(srcIp, dstIp, srcPort, dstPort, protocol, action);
    }

    private static Result<ParseResult> ParseIpv6(string[] fields, EventAction action)
    {
        if (fields.Length < MinFieldsForIpv6)
        {
            return new FormatError();
        }

        var protocol = fields[12].ToProtocol();
        var srcIp = fields[15];
        var dstIp = fields[16];
        int? srcPort = null;
        int? dstPort = null;

        if (fields.Length > 18 && HasPorts(protocol))
        {
            srcPort = fields[17].ToPort();
            dstPort = fields[18].ToPort();
        }

        return new ParseResult(srcIp, dstIp, srcPort, dstPort, protocol, action);
    }

    private static bool HasPorts(EventProtocol protocol) =>
        protocol is EventProtocol.Tcp or EventProtocol.Udp;

    private static EventAction ResolveAction(string action) =>
        action switch
        {
            "pass" => EventAction.Allow,
            "block" => EventAction.Drop,    // pf block = silent discard, no response sent
            "reject" => EventAction.Deny,   // pf reject = active response (TCP RST / ICMP unreachable)
            _ => EventAction.Unknown,
        };

    // Captures the CSV payload from all pfSense/Netgate syslog header formats:
    //   BSD (with PID):    filterlog[pid]: CSV
    //   BSD (without PID): filterlog: CSV
    //   RFC 5424:          filterlog PID - - CSV
    [GeneratedRegex(
        @"filterlog(?:(?:\[\d+\])?:\s+|\s+\d+\s+-\s+-\s+)(?<csv>.+)$",
        RegexOptions.None,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex LogPattern();
}
