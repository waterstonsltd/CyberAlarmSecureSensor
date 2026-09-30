using System.Text.RegularExpressions;
using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Parsing.Errors;
using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Parsing.Draytek;

// Parses Draytek router/firewall filter log messages of the form:
//   ...[FILTER][Pass][LAN/RT/VPN->WAN, ...][@S:R=rule, srcIP:srcPort->dstIP:dstPort][TCP][...]
//   ...[FILTER][Pass][WAN->LAN/RT/VPN, ...][@S:R=rule, srcIP->dstIP][ICMP][...]
//   ...[FILTER][Pass][WAN->LAN/RT/VPN, ...][@S:R=rule, srcIP->dstIP][PR 47][...]
//
// Action values: Pass → Allow, Block → Deny, Drop → Drop.
// ICMP and other non-TCP/UDP protocols omit ports — src_port and dst_port groups are optional.
// Draytek uses [PR N] notation for protocols not named explicitly, where N is the IANA protocol number.
internal sealed partial class DraytekParser : IParser
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

        var sourceIp = match.From("src_ip");
        var destinationIp = match.From("dst_ip");
        var sourcePort = match.NumberFrom("src_port");
        var destinationPort = match.NumberFrom("dst_port");
        var protocol = ResolveProtocol(match.From("proto"), match.From("proto_num"));
        var action = ResolveAction(match.From("action"));

        return new ParseResult(sourceIp, destinationIp, sourcePort, destinationPort, protocol, action);
    }

    private static EventAction ResolveAction(string action) =>
        action switch
        {
            "Pass" => EventAction.Allow,
            "Block" => EventAction.Deny,
            "Drop" => EventAction.Drop,
            _ => EventAction.Unknown,
        };

    private static EventProtocol ResolveProtocol(string proto, string protoNum)
    {
        if (!string.IsNullOrEmpty(protoNum) && int.TryParse(protoNum, out var number))
        {
            var byNumber = (EventProtocol)number;
            return Enum.IsDefined(byNumber) ? byNumber : EventProtocol.Unknown;
        }

        return proto.ToProtocol();
    }

    // Matches the Draytek FILTER log structure.
    // Group layout:
    //   action     — Pass | Block | Drop
    //   src_ip     — source IP address
    //   src_port   — source port (absent for ICMP / non-TCP/UDP)
    //   dst_ip     — destination IP address
    //   dst_port   — destination port (absent for ICMP / non-TCP/UDP)
    //   proto      — named protocol: TCP | UDP | ICMP etc.
    //   proto_num  — numeric protocol from [PR N] notation (IANA number)
    [GeneratedRegex(
        @"\[FILTER\]\[(?<action>\w+)\]\[[^\]]+\]\[@S:R=[^,]+,\s+(?<src_ip>[\d.]+)(?::(?<src_port>\d+))?->(?<dst_ip>[\d.]+)(?::(?<dst_port>\d+))?\]\[(?:(?<proto>\w+)|PR (?<proto_num>\d+))\]",
        RegexOptions.None,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex LogPattern();
}
