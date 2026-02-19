namespace CyberAlarm.SyslogRelay.Common.Models;

public enum EventProtocol
{
    Unknown = 0,
    Icmp = 1,
    Tcp = 6,
    Udp = 17,
    Ipv6 = 41,
    Gre = 47,
    Esp = 50,
    Ah = 51,
    Ospf = 89,
    Sctp = 132,
}
