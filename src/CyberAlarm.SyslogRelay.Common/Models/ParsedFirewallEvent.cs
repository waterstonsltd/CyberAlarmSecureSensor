namespace CyberAlarm.SyslogRelay.Common.Models;

public sealed record ParsedFirewallEvent(
    string SourceIp,
    string? DestinationIp,
    int? SourcePort,
    int? DestinationPort,
    EventProtocol Protocol,
    EventAction Action);
