using CyberAlarm.SyslogRelay.Common.Models;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class ParsedEventBuilder
{
    private readonly DateTime _timestamp = DateTime.UtcNow;
    private string? _rawData = Guid.NewGuid().ToString();

    private EventSource _eventSource = new(IngestionMethod.File, "source");
    private ValidationStatus _validationStatus = ValidationStatus.Success;
    private string? _patternName;
    private ParseResult? _parseResult;

    public ParsedEvent Build() =>
        new(_timestamp, _eventSource, _rawData, _patternName, _parseResult, _validationStatus);

    public ParsedEventBuilder WithSource(string source)
    {
        _eventSource = _eventSource with { Source = source };
        return this;
    }

    public ParsedEventBuilder WithValidationStatus(ValidationStatus validationStatus)
    {
        _validationStatus = validationStatus;
        return this;
    }

    public ParsedEventBuilder WithRawData(string? rawData)
    {
        _rawData = rawData;
        return this;
    }

    public ParsedEventBuilder WithPatternName(string? patternName)
    {
        _patternName = patternName;
        return this;
    }

    public ParsedEventBuilder WithParseResult(ParseResult? parseResult)
    {
        _parseResult = parseResult;
        return this;
    }
}
