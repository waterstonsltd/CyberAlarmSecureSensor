namespace CyberAlarm.SyslogRelay.Common.Models;

public sealed record ParseResult(
    string SourceIp,
    string? DestinationIp,
    int? SourcePort,
    int? DestinationPort,
    EventProtocol Protocol,
    EventAction Action);
