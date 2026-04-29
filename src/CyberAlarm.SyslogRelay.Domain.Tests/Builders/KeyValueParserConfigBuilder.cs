using CyberAlarm.SyslogRelay.Common.Models.ParserConfiguration;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class KeyValueParserConfigBuilder : ParserConfigBuilderBase<KeyValueParserConfig>
{
    private bool? _useRegex;
    private string? _regexPatternOverride;
    private string? _pairDelimiter;
    private string? _valueDelimiter;

    public override KeyValueParserConfig Build() =>
        new()
        {
            UseRegex = _useRegex,
            RegexPatternOverride = _regexPatternOverride,
            PairDelimiter = _pairDelimiter,
            ValueDelimiter = _valueDelimiter,
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

    public KeyValueParserConfigBuilder UseRegex(bool useRegex)
    {
        _useRegex = useRegex;
        return this;
    }

    public KeyValueParserConfigBuilder WithRegexPatternOverride(string regexPatternOverride)
    {
        _regexPatternOverride = regexPatternOverride;
        return this;
    }

    public KeyValueParserConfigBuilder WithDelimiters(string pairDelimiter, string valueDelimiter)
    {
        _pairDelimiter = pairDelimiter;
        _valueDelimiter = valueDelimiter;

        return this;
    }
}
