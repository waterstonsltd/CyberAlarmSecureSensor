using System.Text.RegularExpressions;

namespace CyberAlarm.SyslogRelay.Domain.Parsing.Cisco;

internal sealed class CiscoFirepowerAsaStyleParser : CiscoAsaParserBase
{
    protected override Regex GetMainPattern() => CiscoFirepowerAsaStyleRegexes.MainPattern();
}
