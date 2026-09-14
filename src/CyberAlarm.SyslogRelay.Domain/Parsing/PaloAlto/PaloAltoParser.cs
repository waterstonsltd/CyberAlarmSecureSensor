using System.Globalization;
using System.Text.RegularExpressions;
using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Parsing.Errors;
using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Parsing.PaloAlto;

// Parses Palo Alto PAN-OS TRAFFIC and THREAT log messages forwarded via syslog.
// The syslog message payload is a comma-separated CSV string with positional fields.
//
// Syslog format (RFC 5424 with optional octet-count prefix):
//   [octet_count ]<PRI>1 TIMESTAMP HOSTNAME - - - - CSV
//
// CSV field layout (0-indexed) — shared across TRAFFIC and THREAT:
//   [3]=type  [4]=subtype  [7]=src_ip  [8]=dst_ip
//   [24]=src_port  [25]=dst_port  [29]=protocol  [30]=action
//
// TRAFFIC-only additional fields:
//   [31]=bytes_total  [36]=elapsed_secs
//
// THREAT field [31] is "Misc" (threat name) — not bytes.
//
// Action semantics:
//   allow          → Allow
//   deny           → Deny (sends TCP RST / ICMP unreachable to sender)
//   drop           → Drop (silent discard, no response sent)
//   reset-client   → Deny (TCP RST sent to client only)
//   reset-server   → Deny (TCP RST sent to server only)
//   reset-both     → Deny (TCP RST sent to both endpoints)
internal sealed partial class PaloAltoParser : IParser
{
    private const int MinFields = 31;
    private const int MinFieldsForBytesAndDuration = 37;

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

        if (fields.Length < MinFields)
        {
            return new FormatError();
        }

        var logType = fields[3];
        if (logType != "TRAFFIC" && logType != "THREAT")
        {
            return new FormatError();
        }

        var action = ResolveAction(fields[30]);
        var protocol = fields[29].ToProtocol();
        var srcIp = fields[7];
        var dstIp = fields[8];
        int? srcPort = null;
        int? dstPort = null;

        if (HasPorts(protocol))
        {
            srcPort = fields[24].ToPort();
            dstPort = fields[25].ToPort();
        }

        long? bytes = null;
        TimeSpan? duration = null;

        if (logType == "TRAFFIC" && fields.Length >= MinFieldsForBytesAndDuration)
        {
            bytes = fields[31].ToLong();

            if (long.TryParse(fields[36], NumberStyles.Integer, CultureInfo.InvariantCulture, out var elapsed))
            {
                duration = TimeSpan.FromSeconds(elapsed);
            }
        }

        return new ParseResult(srcIp, dstIp, srcPort, dstPort, protocol, action, duration, bytes);
    }

    private static bool HasPorts(EventProtocol protocol) =>
        protocol is EventProtocol.Tcp or EventProtocol.Udp;

    private static EventAction ResolveAction(string action) =>
        action switch
        {
            "allow" => EventAction.Allow,
            "deny" => EventAction.Deny,         // active rejection — RST / ICMP unreachable sent to sender
            "drop" => EventAction.Drop,         // silent discard — no response sent
            "reset-client" => EventAction.Deny, // TCP RST sent to client only
            "reset-server" => EventAction.Deny, // TCP RST sent to server only
            "reset-both" => EventAction.Deny,   // TCP RST sent to both endpoints
            _ => EventAction.Unknown,
        };

    // Matches PAN-OS syslog with optional octet-count prefix.
    // Supports both RFC 5424 and RFC 3164 (BSD-style) formats:
    //   RFC 5424: <PRI>1 TIMESTAMP HOSTNAME - - - - CSV
    //   RFC 3164: <PRI>Mon DD HH:MM:SS HOSTNAME CSV
    // The CSV payload always begins with "1," (future-use field).
    [GeneratedRegex(
        @"(?:\d+\s+)?<\d+>(?:1\s+\S+\s+\S+\s+-\s+-\s+-\s+-\s+|\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+)(?<csv>1,.+)$",
        RegexOptions.None,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex LogPattern();
}
