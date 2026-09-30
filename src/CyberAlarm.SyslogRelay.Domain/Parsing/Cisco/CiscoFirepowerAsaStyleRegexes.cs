using System.Text.RegularExpressions;

namespace CyberAlarm.SyslogRelay.Domain.Parsing.Cisco;

internal static partial class CiscoFirepowerAsaStyleRegexes
{
    // Matches ASA-style FTD syslog messages such as:
    //   <166>Apr 24 2026 13:45:44: %FTD-6-302013: Built inbound TCP connection ...
    //   %FTD-4-106023: Deny udp src ...
    [GeneratedRegex(@"(?:[^%]*)?%FTD-(?:\w+-)?(?<severity>\d)-(?<message_id>\d{6}):\s+(?<message_content>.+)$", RegexOptions.Compiled)]
    public static partial Regex MainPattern();
}
