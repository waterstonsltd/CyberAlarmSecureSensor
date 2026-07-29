using CyberAlarm.SyslogRelay.Common.Models.ParserConfiguration;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal abstract class ParserConfigBuilderBase<TParserConfig>
    where TParserConfig : ParserConfig
{
    protected string[] _sourceIpKeys = [];
    protected string[] _destinationIpKeys = [];
    protected bool _isDestinationIpOptional;
    protected string[] _sourcePortKeys = [];
    protected bool _isSourcePortOptional;
    protected string[] _destinationPortKeys = [];
    protected bool _isDestinationPortOptional;
    protected string[] _protocolKeys = [];
    protected bool _isProtocolOptional;
    protected string[] _actionKeys = [];
    protected bool _isActionOptional;
    protected string[] _allowActionValues = [];
    protected string[] _denyActionValues = [];
    protected string[] _dropActionValues = [];
    protected string[] _closeActionValues = [];
    protected string[] _resetActionValues = [];
    protected string[] _timeoutActionValues = [];
    protected string[] _durationKeys = [];
    protected bool _durationIsSeconds;
    protected string[] _totalBytesKeys = [];
    protected string[] _sentBytesKeys = [];
    protected string[] _receivedBytesKeys = [];

    public abstract TParserConfig Build();

    public ParserConfigBuilderBase<TParserConfig> WithSourceIpKeys(params string[] keys)
    {
        _sourceIpKeys = keys;
        return this;
    }

    public ParserConfigBuilderBase<TParserConfig> WithDestinationIpKeys(params string[] keys)
    {
        _destinationIpKeys = keys;
        return this;
    }

    public ParserConfigBuilderBase<TParserConfig> WithSourcePortKeys(params string[] keys)
    {
        _sourcePortKeys = keys;
        return this;
    }

    public ParserConfigBuilderBase<TParserConfig> WithDestinationPortKeys(params string[] keys)
    {
        _destinationPortKeys = keys;
        return this;
    }

    public ParserConfigBuilderBase<TParserConfig> WithProtocolKeys(params string[] keys)
    {
        _protocolKeys = keys;
        return this;
    }

    public ParserConfigBuilderBase<TParserConfig> WithActionKeys(params string[] keys)
    {
        _actionKeys = keys;
        return this;
    }

    public ParserConfigBuilderBase<TParserConfig> WithActionValues(
        string[]? allowValues = null,
        string[]? denyValues = null,
        string[]? dropValues = null,
        string[]? closeValues = null,
        string[]? resetValues = null,
        string[]? timeoutValues = null)
    {
        _allowActionValues = allowValues ?? [];
        _denyActionValues = denyValues ?? [];
        _dropActionValues = dropValues ?? [];
        _closeActionValues = closeValues ?? [];
        _resetActionValues = resetValues ?? [];
        _timeoutActionValues = timeoutValues ?? [];

        return this;
    }

    public ParserConfigBuilderBase<TParserConfig> WithOptional(
        bool destinationIp = true,
        bool sourcePort = true,
        bool destinationPort = true,
        bool protocol = true,
        bool action = true)
    {
        _isDestinationIpOptional = destinationIp;
        _isSourcePortOptional = sourcePort;
        _isDestinationPortOptional = destinationPort;
        _isProtocolOptional = protocol;
        _isActionOptional = action;

        return this;
    }

    public ParserConfigBuilderBase<TParserConfig> WithDurationKeys(bool isSeconds, params string[] keys)
    {
        _durationKeys = keys;
        _durationIsSeconds = isSeconds;
        return this;
    }

    public ParserConfigBuilderBase<TParserConfig> WithTotalBytesKeys(params string[] keys)
    {
        _totalBytesKeys = keys;
        return this;
    }

    public ParserConfigBuilderBase<TParserConfig> WithBytesKeys(string[] sentKeys, string[] receivedKeys)
    {
        _sentBytesKeys = sentKeys;
        _receivedBytesKeys = receivedKeys;
        return this;
    }
}
