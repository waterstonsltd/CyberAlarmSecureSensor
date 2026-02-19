using CyberAlarm.SyslogRelay.Common.Models;
using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Parsing;

internal interface IParser
{
    string Name { get; }

    Result<ParsedFirewallEvent> Parse(string log);
}
