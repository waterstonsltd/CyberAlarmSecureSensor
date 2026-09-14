using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Common.Models.ParserConfiguration;
using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.Parsing;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Parsing;

public sealed class JsonParserTests
{
    private readonly JsonParser _unitUnderTest = new();

    private static JsonParserConfig SmoothwallFirewallConfig() =>
        new()
        {
            JsonStartToken = "firewall: ",
            ProtocolIsNumber = true,
            SourceIpKeys = ["src"],
            DestinationIpKeys = ["dst"],
            IsDestinationIpOptional = true,
            SourcePortKeys = ["spt"],
            IsSourcePortOptional = true,
            DestinationPortKeys = ["dpt"],
            IsDestinationPortOptional = true,
            ProtocolKeys = ["proto"],
            IsProtocolOptional = true,
            ActionKeys = ["action"],
            IsActionOptional = true,
            AllowActionValues = ["accept"],
            DenyActionValues = ["reject"],
            DropActionValues = ["drop"],
        };

    [Theory]
    [InlineData("x")]
    [InlineData("{\"src\":\"1.2.3.4\"}")]
    [InlineData("kernel: SRC=1.2.3.4 DST=5.6.7.8")]
    [InlineData("firewall: not-json")]
    public void Parse_should_fail_when_log_has_incorrect_format(string log)
    {
        // Arrange
        var config = SmoothwallFirewallConfig();
        _unitUnderTest.Initialise(config);

        // Act
        var result = _unitUnderTest.Parse(log);

        // Assert
        Assert.True(result.IsFailed);
        Assert.Equal("Log format is invalid.", result.ErrorMessage);
    }

    [Fact]
    public void Parse_should_fail_when_log_does_not_contain_src()
    {
        // Arrange
        var config = SmoothwallFirewallConfig();
        _unitUnderTest.Initialise(config);

        // Act
        var result = _unitUnderTest.Parse("firewall: {\"action\":\"drop\",\"dst\":\"1.2.3.4\"}");

        // Assert
        Assert.True(result.IsFailed);
        Assert.Equal("Failed to parse event.", result.ErrorMessage);
    }

    [Fact]
    public void Parse_should_fail_when_json_start_token_is_not_followed_by_json_object()
    {
        // Arrange
        var config = SmoothwallFirewallConfig();
        _unitUnderTest.Initialise(config);

        // Act — token is present but the character after it is not '{'
        var result = _unitUnderTest.Parse("firewall: [\"not\",\"an\",\"object\"]");

        // Assert
        Assert.True(result.IsFailed);
        Assert.Equal("Log format is invalid.", result.ErrorMessage);
    }

    [Fact]
    public void Parse_should_use_first_json_object_when_no_start_token_configured()
    {
        // Arrange
        var config = new JsonParserConfig
        {
            JsonStartToken = null,
            ProtocolIsNumber = true,
            SourceIpKeys = ["src"],
            ProtocolKeys = ["proto"],
            DestinationIpKeys = [],
            SourcePortKeys = [],
            DestinationPortKeys = [],
            ActionKeys = [],
            IsDestinationIpOptional = true,
            IsSourcePortOptional = true,
            IsDestinationPortOptional = true,
            IsProtocolOptional = true,
            IsActionOptional = true,
        };
        _unitUnderTest.Initialise(config);

        // Act
        var result = _unitUnderTest.Parse("some prefix {\"src\":\"1.2.3.4\",\"proto\":6}");

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Equal("1.2.3.4", result.Value.SourceIp);
        Assert.Equal(EventProtocol.Tcp, result.Value.Protocol);
    }

    [Theory]
    [MemberData(nameof(SmoothwallFirewallJsonTestLogs), MemberType = typeof(JsonParserTests))]
    public void Parse_should_succeed_when_log_has_correct_format(JsonParserConfig config, string log, ParseResult parseResult)
    {
        // Arrange
        _unitUnderTest.Initialise(config);

        // Act
        var result = _unitUnderTest.Parse(log);

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Equal(parseResult, result.Value);
    }

    public static TheoryData<JsonParserConfig, string, ParseResult> SmoothwallFirewallJsonTestLogs()
    {
        var config = SmoothwallFirewallConfig();

        return new()
        {
            {
                config,
                "<13>Apr  8 15:41:29 smoothwall firewall: {\"action\":\"drop\",\"date\":1775659288,\"dpt\":8866,\"dst\":\"192.0.2.1\",\"in\":\"00000000-0000-4000-8000-000000000001\",\"proto\":6,\"rule_type\":\"in-fallback\",\"spt\":26200,\"src\":\"198.51.100.1\"}",
                new("198.51.100.1", "192.0.2.1", 26200, 8866, EventProtocol.Tcp, EventAction.Drop)
            },
            {
                config,
                "<13>Apr  8 15:41:29 smoothwall firewall: {\"action\":\"drop\",\"date\":1775659288,\"dst\":\"192.0.2.2\",\"in\":\"00000000-0000-4000-8000-000000000001\",\"proto\":1,\"rule_type\":\"in-fallback\",\"src\":\"198.51.100.2\"}",
                new("198.51.100.2", "192.0.2.2", null, null, EventProtocol.Icmp, EventAction.Drop)
            },
            {
                config,
                "smoothwall firewall: {\"action\":\"accept\",\"dst\":\"10.0.0.1\",\"proto\":17,\"spt\":5353,\"dpt\":5353,\"src\":\"192.168.1.1\"}",
                new("192.168.1.1", "10.0.0.1", 5353, 5353, EventProtocol.Udp, EventAction.Allow)
            },
            {
                config,
                "firewall: {\"action\":\"drop\",\"proto\":47,\"src\":\"203.0.113.5\",\"dst\":\"192.168.1.1\"}",
                new("203.0.113.5", "192.168.1.1", null, null, EventProtocol.Gre, EventAction.Drop)
            },
            {
                config,
                "firewall: {\"action\":\"unknown\",\"proto\":999,\"src\":\"1.2.3.4\"}",
                new("1.2.3.4", null, null, null, EventProtocol.Unknown, EventAction.Unknown)
            },
            {
                config,
                "firewall: {\"action\":\"reject\",\"proto\":4,\"src\":\"10.0.0.1\",\"dst\":\"10.0.0.2\"}",
                new("10.0.0.1", "10.0.0.2", null, null, EventProtocol.Ipip, EventAction.Deny)
            },
        };
    }
}

