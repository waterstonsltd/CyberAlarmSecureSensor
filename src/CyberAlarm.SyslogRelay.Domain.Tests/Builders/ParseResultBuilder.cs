using CyberAlarm.SyslogRelay.Common.Models;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class ParseResultBuilder
{
    private string _sourceIp = "0.0.0.0";
    private string? _destinationIp = "1.1.1.1";
    private int? _sourcePort = 1234;
    private int? _destinationPort = 4321;
    private EventProtocol _protocol = EventProtocol.Unknown;
    private EventAction _action = EventAction.Unknown;

    public ParseResult Build() =>
        new(_sourceIp, _destinationIp, _sourcePort, _destinationPort, _protocol, _action);

    public ParseResultBuilder WithSourceIp(string sourceIp)
    {
        _sourceIp = sourceIp;
        return this;
    }

    public ParseResultBuilder WithDestinationIp(string? destinationIp)
    {
        _destinationIp = destinationIp;
        return this;
    }
}
