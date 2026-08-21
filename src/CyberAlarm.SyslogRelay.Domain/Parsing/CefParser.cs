using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Common.Models.ParserConfiguration;
using CyberAlarm.SyslogRelay.Domain.Parsing.Errors;
using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Parsing;

internal sealed class CefParser : KeyValueParserBase<ParserConfig>
{
    public const string CefPrefix = "CEF:";
    public const int PipeCount = 7;
    public const char PairDelimiter = ' ';
    public const char ValueDelimiter = '=';

    protected override Result<ParseResult> ParseLog(string log, ParserConfig config)
    {
        if (log.Count('|') != PipeCount)
        {
            return new FormatError();
        }

        var fields = log.Split('|', StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length <= PipeCount)
        {
            return new FormatError();
        }

        if (!fields[0].Contains(CefPrefix))
        {
            return new FormatError();
        }

        var keyValues = fields[^1].ParseKeyValues(PairDelimiter, ValueDelimiter);
        return ParseKeyValues(keyValues, config);
    }
}
