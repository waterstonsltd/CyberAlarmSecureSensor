using FluentResults;

namespace CyberAlarm.SyslogRelay.Common.Models;

public interface IParser
{
    Result Initialise(object? config);

    Result<ParseResult> Parse(string log);
}
