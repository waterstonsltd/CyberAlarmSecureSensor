using System.Text.RegularExpressions;
using CyberAlarm.SyslogRelay.Common.Models;

namespace CyberAlarm.SyslogRelay.Domain.Parsing.Cisco;

internal sealed class ContentParsingInfo
{
    public required Regex Regex { get; init; }

    public bool SkipDestinationIp { get; init; }

    public bool SkipSourcePort { get; init; }

    public bool SkipDestinationPort { get; init; }

    public bool HasProtocolNumber { get; init; }

    public bool SkipProtocol { get; init; }

    public EventProtocol? Protocol { get; init; }

    public EventAction? Action { get; init; }
}
