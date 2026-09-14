using CyberAlarm.SyslogRelay.Common.Models.ParserConfiguration;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class JsonParserConfigBuilder : ParserConfigBuilderBase<JsonParserConfig>
{
    private string? _jsonStartToken;
    private bool _protocolIsNumber;

    public JsonParserConfigBuilder WithJsonStartToken(string token)
    {
        _jsonStartToken = token;
        return this;
    }

    public JsonParserConfigBuilder WithProtocolIsNumber(bool value = true)
    {
        _protocolIsNumber = value;
        return this;
    }

    public override JsonParserConfig Build() =>
        new()
        {
            JsonStartToken = _jsonStartToken,
            ProtocolIsNumber = _protocolIsNumber,
            SourceIpKeys = _sourceIpKeys,
            DestinationIpKeys = _destinationIpKeys,
            IsDestinationIpOptional = _isDestinationIpOptional,
            SourcePortKeys = _sourcePortKeys,
            IsSourcePortOptional = _isSourcePortOptional,
            DestinationPortKeys = _destinationPortKeys,
            IsDestinationPortOptional = _isDestinationPortOptional,
            ProtocolKeys = _protocolKeys,
            IsProtocolOptional = _isProtocolOptional,
            ActionKeys = _actionKeys,
            IsActionOptional = _isActionOptional,
            AllowActionValues = _allowActionValues,
            DenyActionValues = _denyActionValues,
            DropActionValues = _dropActionValues,
            CloseActionValues = _closeActionValues,
            ResetActionValues = _resetActionValues,
            TimeoutActionValues = _timeoutActionValues,
            DurationKeys = _durationKeys,
            DurationIsSeconds = _durationIsSeconds,
            TotalBytesKeys = _totalBytesKeys,
            SentBytesKeys = _sentBytesKeys,
            ReceivedBytesKeys = _receivedBytesKeys,
        };
}
