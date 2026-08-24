using System.Text.RegularExpressions;
using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Parsing.Errors;
using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Parsing.Barracuda;

// Parses Barracuda CloudGen Firewall key-value pair (KVP) syslog messages.
//
// Syslog format (RFC 3164):
//   <PRI>Mon DD HH:MM:SS HOSTNAME HOSTNAME/box_Firewall_Activity:  SEVERITY     HOSTNAME ACTION: KVP_PAYLOAD
//
// KVP payload: pipe-separated key=value pairs.
//   Notable keys: type, proto, srcIF, srcIP, srcPort, srcMAC, dstIP, dstPort,
//                 dstService, dstIF, rule, info, srcNAT, dstNAT,
//                 duration, count, receivedBytes, sentBytes, ...
//
// Action semantics:
//   Allow  → Allow (traffic forwarded)
//   Block  → Drop  (silent discard — no TCP RST sent)
//   Detect → Allow (application identification event; traffic was forwarded)
internal sealed partial class BarracudaCgfKvpParser : IParser
{
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
        var kvp = ParseKvp(match.Groups["payload"].Value);

        if (!kvp.TryGetValue("srcIP", out var srcIp) || string.IsNullOrEmpty(srcIp))
        {
            return new FormatError();
        }

        kvp.TryGetValue("dstIP", out var dstIp);

        var protocol = kvp.TryGetValue("proto", out var protoValue)
            ? BarracudaCgfHelper.ResolveProtocol(protoValue)
            : EventProtocol.Unknown;

        int? srcPort = null;
        int? dstPort = null;

        if (BarracudaCgfHelper.HasPorts(protocol))
        {
            if (kvp.TryGetValue("srcPort", out var srcPortValue))
            {
                srcPort = srcPortValue.ToPort();
            }

            if (kvp.TryGetValue("dstPort", out var dstPortValue))
            {
                dstPort = dstPortValue.ToPort();
            }
        }

        var duration = kvp.ExtractDuration(["duration"], durationIsSeconds: true);
        var bytes = kvp.ExtractBytes([], ["sentBytes"], ["receivedBytes"]);

        return new ParseResult(srcIp, dstIp, srcPort, dstPort, protocol, action, duration, bytes);
    }

    private static Dictionary<string, string> ParseKvp(string payload) =>
        payload
            .Split('|')
            .Select(pair => pair.Split('=', 2))
            .Where(parts => parts.Length == 2)
            .GroupBy(parts => parts[0], StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First()[1], StringComparer.OrdinalIgnoreCase);

    [GeneratedRegex(
        @"^<\d+>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+/box_Firewall_Activity:\s+\w+\s+\S+\s+(?<action>Allow|Block|Detect):\s+(?<payload>.+)$",
        RegexOptions.None,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex LogPattern();
}
