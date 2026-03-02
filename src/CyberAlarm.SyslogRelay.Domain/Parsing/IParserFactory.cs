using CyberAlarm.SyslogRelay.Common.Models;

namespace CyberAlarm.SyslogRelay.Domain.Parsing;

internal interface IParserFactory
{
    IParser? Create(string parserName);
}
