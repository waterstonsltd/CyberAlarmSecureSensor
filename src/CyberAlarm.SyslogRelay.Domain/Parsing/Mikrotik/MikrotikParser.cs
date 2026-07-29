using System.Text.RegularExpressions;
using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Parsing.Errors;
using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Parsing.Mikrotik;

// Parses MikroTik RouterOS firewall log messages produced by action=log rules.
//
// RouterOS does not embed an action field in log messages - the action (accept/drop/deny)
// must be encoded by the administrator in the log-prefix of each firewall rule.
//
// Expected syslog payload format:
//   firewall,<severity> <prefix>: <rule-name> <chain>: in:<in-iface> out:<out-iface>,
//     connection-state:<state>[,<nat>] [src-mac <mac>], proto <protocol>[ (<flags>)],
//     <src-ip>[:<src-port>]-><dst-ip>[:<dst-port>][, NAT ...], len <len>
//
// Action is inferred from pca-* keywords in the log-prefix:
//   pca-accept / pca-allow → Allow
//   pca-drop               → Drop
//   pca-deny / pca-reject  → Deny (pca-reject sends TCP RST / ICMP unreachable)
//
// NAT handling:
//   Outbound SNAT produces "NAT (internal->external)->dst" in the log. In this case
//   the pre-NAT source is the internal LAN IP, so we extract the external (public) IP
//   from the NAT section instead. Inbound DNAT has "NAT src->(external->internal)" form
//   and does not match the outbound NAT pattern, so the pre-NAT source is used as-is.
internal sealed partial class MikrotikParser : IParser
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

        var action = ResolveAction(match.From("prefix"));
        var protocol = match.From("proto").ToProtocol();

        // For outbound SNAT the pre-NAT source is the internal IP.
        // Override with the external (public) address from the NAT section.
        var natMatch = NatOutboundPattern().Match(log);
        string srcIp;
        string dstIp;
        int? srcPort;
        int? dstPort;

        if (natMatch.Success)
        {
            srcIp = natMatch.From("src");
            dstIp = natMatch.From("dst");
            srcPort = natMatch.NumberFrom("sport");
            dstPort = natMatch.NumberFrom("dport");
        }
        else
        {
            srcIp = match.From("src");
            dstIp = match.From("dst");
            srcPort = match.NumberFrom("sport");
            dstPort = match.NumberFrom("dport");
        }

        return new ParseResult(srcIp, dstIp, srcPort, dstPort, protocol, action);
    }

    private static EventAction ResolveAction(string prefix) =>
        prefix.ToLowerInvariant() switch
        {
            var p when p.Contains("pca-accept") || p.Contains("pca-allow") => EventAction.Allow,
            var p when p.Contains("pca-drop") => EventAction.Drop,
            var p when p.Contains("pca-reject") || p.Contains("pca-deny") => EventAction.Deny,
            _ => EventAction.Unknown,
        };

    // Matches the firewall log preamble and pre-NAT address pair.
    //   Group 'prefix' – the log-prefix token (e.g. pca-accept, pca-deny)
    //   Group 'proto'  – protocol name (e.g. TCP, UDP, ICMP)
    //   Group 'src'    – source IPv4 address (may be internal for outbound SNAT)
    //   Group 'sport'  – source port (optional; absent for ICMP)
    //   Group 'dst'    – destination IPv4 address
    //   Group 'dport'  – destination port (optional; absent for ICMP)
    [GeneratedRegex(
        @"^firewall,\w+\s+(?<prefix>[^:]+):.+?proto\s+(?<proto>\w+)(?:\s*\([^)]*\))?,\s+(?<src>\d{1,3}(?:\.\d{1,3}){3})(?::(?<sport>\d+))?->(?<dst>\d{1,3}(?:\.\d{1,3}){3})(?::(?<dport>\d+))?",
        RegexOptions.None,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex LogPattern();

    // Matches outbound SNAT NAT sections of the form "NAT (internal->external)->dst".
    // When present, the external source IP/port should be used in place of the pre-NAT source.
    //   Group 'src'   – external (public) source IPv4 address
    //   Group 'sport' – external source port (optional; absent for ICMP)
    //   Group 'dst'   – destination IPv4 address
    //   Group 'dport' – destination port (optional; absent for ICMP)
    [GeneratedRegex(
        @",\s+NAT\s+\([^>]+>(?<src>\d{1,3}(?:\.\d{1,3}){3})(?::(?<sport>\d+))?\)->(?<dst>\d{1,3}(?:\.\d{1,3}){3})(?::(?<dport>\d+))?",
        RegexOptions.None,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex NatOutboundPattern();
}
