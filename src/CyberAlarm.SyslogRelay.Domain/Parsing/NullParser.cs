using CyberAlarm.SyslogRelay.Common.Models;
using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Parsing;

internal sealed class NullParser : IParser
{
    public string Name => nameof(NullParser);

    public Result<ParseResult> Parse(string log)
    {
        return Result.Fail<ParseResult>($"{Name} does not parse any logs.");
    }
}
