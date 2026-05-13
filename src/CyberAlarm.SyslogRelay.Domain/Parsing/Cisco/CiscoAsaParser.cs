using System.Text.RegularExpressions;

namespace CyberAlarm.SyslogRelay.Domain.Parsing.Cisco;

internal sealed class CiscoAsaParser : CiscoAsaParserBase
{
    protected override Regex GetMainPattern() => CiscoAsaRegexes.MainPattern();
}
