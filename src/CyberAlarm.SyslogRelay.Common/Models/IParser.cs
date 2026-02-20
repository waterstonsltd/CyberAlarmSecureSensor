using FluentResults;

namespace CyberAlarm.SyslogRelay.Common.Models;

public interface IParser
{
    string Name { get; }

    Result<ParseResult> Parse(string log);
}
