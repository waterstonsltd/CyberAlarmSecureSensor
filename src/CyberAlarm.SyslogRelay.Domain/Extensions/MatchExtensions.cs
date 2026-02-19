using System.Diagnostics.CodeAnalysis;
using System.Text.RegularExpressions;
using CyberAlarm.SyslogRelay.Common.Models;

namespace CyberAlarm.SyslogRelay.Domain.Extensions;

[SuppressMessage("Minor Code Smell", "S2325:Methods and properties that don't access instance data should be static", Justification = "Ok for extension methods.")]
public static class MatchExtensions
{
    extension(Match match)
    {
        public string SourceIp(string groupKey = "src_ip") =>
            match.Groups[groupKey].Value;

        public string DestinationIp(string groupKey = "dst_ip") =>
            match.Groups[groupKey].Value;

        public int SourcePort(string groupKey = "src_port") =>
            int.Parse(match.Groups[groupKey].Value);

        public int DestinationPort(string groupKey = "dst_port") =>
            int.Parse(match.Groups[groupKey].Value);

        public EventProtocol Protocol(string groupKey = "protocol") =>
            match.AnyProtocol(groupKey);

        public EventProtocol ProtocolNumber(string groupKey = "protocol_num") =>
            match.AnyProtocol(groupKey);

        public EventAction Action(string groupKey = "action") =>
            match.Groups[groupKey].Value?.ToLower() switch
            {
                "permitted" => EventAction.Allow,
                "denied" => EventAction.Deny,
                _ => EventAction.Unknown,
            };

        private EventProtocol AnyProtocol(string groupKey) =>
            Enum.TryParse<EventProtocol>(match.Groups[groupKey].Value, true, out var protocol) && Enum.IsDefined(protocol)
            ? protocol
            : EventProtocol.Unknown;
    }
}
