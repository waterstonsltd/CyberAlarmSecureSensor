using System.Text.Json.Serialization;

namespace CyberAlarm.SyslogRelay.Common.Models;

[JsonConverter(typeof(JsonStringEnumConverter<EventProtocol>))]
public enum EventProtocol
{
    Unknown = 0,
    Icmp = 1,
    Igmp = 2,
    Tcp = 6,
    Udp = 17,
    Ipv6 = 41,
    Gre = 47,
    Esp = 50,
    Ah = 51,
    Icmpv6 = 58,
    Ospf = 89,
    Pim = 103,
    Vrrp = 112,
    Sctp = 132,
}
