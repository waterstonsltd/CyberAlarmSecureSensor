using CyberAlarm.SyslogRelay.Common.Models;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class ParsedEventBuilder
{
    private readonly DateTime _timestamp = DateTime.UtcNow;
    private readonly string _rawData = Guid.NewGuid().ToString();

    private EventSource _eventSource = new(IngestionMethod.File, "source");

    public ParsedEvent Build() =>
        new(_timestamp, _eventSource, _rawData, null, null);

    public ParsedEventBuilder WithSource(string source)
    {
        _eventSource = _eventSource with { Source = source };
        return this;
    }
}
