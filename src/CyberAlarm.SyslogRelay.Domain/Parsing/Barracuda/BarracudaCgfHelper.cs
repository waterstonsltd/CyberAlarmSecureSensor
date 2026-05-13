using CyberAlarm.SyslogRelay.Common.Models;

namespace CyberAlarm.SyslogRelay.Domain.Parsing.Barracuda;

internal static class BarracudaCgfHelper
{
    internal static bool HasPorts(EventProtocol protocol) =>
        protocol is EventProtocol.Tcp or EventProtocol.Udp;

    // Barracuda appends the IANA protocol number in parentheses for protocols it does not name,
    // e.g. "IGMP(2)". Try a plain name-parse first; if that yields Unknown, extract the number
    // and cast it to EventProtocol so that enum-defined protocols (Igmp=2, Esp=50, etc.) resolve.
    internal static EventProtocol ResolveProtocol(string proto)
    {
        var protocol = proto.ToProtocol();
        if (protocol != EventProtocol.Unknown)
        {
            return protocol;
        }

        var parenStart = proto.IndexOf('(');
        if (parenStart > 0 && proto.EndsWith(')') &&
            int.TryParse(proto.AsSpan(parenStart + 1, proto.Length - parenStart - 2), out var number))
        {
            var byNumber = (EventProtocol)number;
            return Enum.IsDefined(byNumber) ? byNumber : EventProtocol.Unknown;
        }

        return EventProtocol.Unknown;
    }

    // Allow/Detect both represent traffic being forwarded; Block is a silent discard (no TCP RST).
    internal static EventAction ResolveActivityAction(string action) =>
        action switch
        {
            "Allow" => EventAction.Allow,
            "Detect" => EventAction.Allow,
            "Block" => EventAction.Drop,
            _ => EventAction.Unknown,
        };
}
