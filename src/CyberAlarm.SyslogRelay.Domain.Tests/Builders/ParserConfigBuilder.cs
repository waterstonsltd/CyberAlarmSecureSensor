using CyberAlarm.SyslogRelay.Common.Models.ParserConfiguration;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class ParserConfigBuilder : ParserConfigBuilderBase<ParserConfig>
{
    public override ParserConfig Build() =>
        new()
        {
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
