namespace CyberAlarm.SyslogRelay.Common.Models;

public sealed record ParsingStageOutput(
    SyslogEvent SyslogEvent,
    MatchedFirewallEvent? MatchedFirewallEvent,
    ParsedFirewallEvent? ParsedFirewallEvent);
