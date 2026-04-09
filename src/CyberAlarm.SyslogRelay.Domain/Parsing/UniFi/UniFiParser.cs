using System.Text.RegularExpressions;
using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Common.Models.ParserConfiguration;
using CyberAlarm.SyslogRelay.Domain.Parsing.Errors;
using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Parsing.UniFi;

// Parses UniFi/UDM firewall kernel log messages of the form:
//   [ZONE-A-RULENUM] ... SRC=x DST=x ... PROTO=TCP SPT=x DPT=x ...
// The action letter (A = allow, D = deny) is embedded in the rule-chain bracket.
//
// UniFi kernel logs can repeat keys (e.g. ID= appears twice for IP-ID and ICMP-ID,
// LEN= appears twice for IP length and UDP payload length). The regex-based key-value
// parser is used instead of the simple space-split parser so that duplicate keys are
// silently overwritten (last-write-wins) rather than throwing on dictionary insert.
internal sealed partial class UniFiParser : KeyValueParserBase<ParserConfig>
{
    protected override Result<ParseResult> ParseLog(string log, ParserConfig config)
    {
        var actionMatch = ActionRegex().Match(log);
        if (!actionMatch.Success)
        {
            return new FormatError();
        }

        var buffer = new Dictionary<string, string>(32);
        var keyValues = log.ParseKeyValues(buffer);

        if (keyValues is null ||
            !TryGetValue(keyValues, config.SourceIpKeys, out var sourceIp) ||
            (!TryGetValue(keyValues, config.DestinationIpKeys, out var destinationIp) && !config.IsDestinationIpOptional) ||
            (!TryGetValue(keyValues, config.SourcePortKeys, out var sourcePortValue) && !config.IsSourcePortOptional) ||
            (!TryGetValue(keyValues, config.DestinationPortKeys, out var destinationPortValue) && !config.IsDestinationPortOptional) ||
            (!TryGetValue(keyValues, config.ProtocolKeys, out var protocolValue) && !config.IsProtocolOptional))
        {
            return new UnparsableEventError();
        }

        return ToParseResult(
            config,
            sourceIp,
            destinationIp,
            sourcePortValue,
            destinationPortValue,
            protocolValue,
            actionMatch.Groups[1].Value,
            ExtractDuration(keyValues, config),
            ExtractBytes(keyValues, config));
    }

    // Matches the UniFi rule-chain bracket: [ZONENAME-X-RULENUM]
    // where X is a single uppercase letter (A = allow, D = deny).
    // Group 1 captures the action letter.
    [GeneratedRegex(@"\[\w+-([A-Z])-\d+\]")]
    private static partial Regex ActionRegex();
}
