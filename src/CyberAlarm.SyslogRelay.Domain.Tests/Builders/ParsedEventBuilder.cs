using CyberAlarm.SyslogRelay.Common.Models;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class ParsedEventBuilder
{
    private readonly DateTime _timestamp = DateTime.UtcNow;
    private readonly string _rawData = Guid.NewGuid().ToString();

    private EventSource _eventSource = new(IngestionMethod.File, "source");
    private ValidationStatus _validationStatus = ValidationStatus.Success;

    public ParsedEvent Build() =>
        new(_timestamp, _eventSource, _rawData, null, null, _validationStatus);

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
}
