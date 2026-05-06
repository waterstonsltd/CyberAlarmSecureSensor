using CyberAlarm.SyslogRelay.Common.Models;
using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Parsing;

internal sealed class NullParser : IParser
{
    public Result Initialise(object? config) => Result.Ok();

    public Result<ParseResult> Parse(string log)
    {
        return Result.Fail<ParseResult>($"{nameof(NullParser)} does not parse any logs.");
    }
}
