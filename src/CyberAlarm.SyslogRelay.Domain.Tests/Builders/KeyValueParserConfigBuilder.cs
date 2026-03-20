using CyberAlarm.SyslogRelay.Common.Models.ParserConfiguration;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class KeyValueParserConfigBuilder
{
    private string _regexPattern = string.Empty;
    private string[] _sourceIpKeys = [];
    private string[] _destinationIpKeys = [];
    private bool _isDestinationIpOptional;
    private string[] _sourcePortKeys = [];
    private bool _isSourcePortOptional;
    private string[] _destinationPortKeys = [];
    private bool _isDestinationPortOptional;
    private string[] _protocolKeys = [];
    private bool _isProtocolOptional;
    private string[] _actionKeys = [];
    private bool _isActionOptional;
    private string[] _allowActionValues = [];
    private string[] _denyActionValues = [];

    public KeyValueParserConfig Build() =>
        new()
        {
            RegexPattern = _regexPattern,
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
        };

    public KeyValueParserConfigBuilder WithRegexPattern(string regexPattern)
    {
        _regexPattern = regexPattern;
        return this;
    }

    public KeyValueParserConfigBuilder WithSourceIpKeys(params string[] keys)
    {
        _sourceIpKeys = keys;
        return this;
    }

    public KeyValueParserConfigBuilder WithDestinationIpKeys(params string[] keys)
    {
        _destinationIpKeys = keys;
        return this;
    }

    public KeyValueParserConfigBuilder WithSourcePortKeys(params string[] keys)
    {
        _sourcePortKeys = keys;
        return this;
    }

    public KeyValueParserConfigBuilder WithDestinationPortKeys(params string[] keys)
    {
        _destinationPortKeys = keys;
        return this;
    }

    public KeyValueParserConfigBuilder WithProtocolKeys(params string[] keys)
    {
        _protocolKeys = keys;
        return this;
    }

    public KeyValueParserConfigBuilder WithActionKeys(params string[] keys)
    {
        _actionKeys = keys;
        return this;
    }

    public KeyValueParserConfigBuilder WithActionValues(string[] allowValues, string[] denyValues)
    {
        _allowActionValues = allowValues;
        _denyActionValues = denyValues;

        return this;
    }

    public KeyValueParserConfigBuilder WithOptional(
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
}
