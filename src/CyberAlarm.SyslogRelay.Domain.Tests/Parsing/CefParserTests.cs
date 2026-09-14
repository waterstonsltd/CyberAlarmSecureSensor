using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Common.Models.ParserConfiguration;
using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.Parsing;
using CyberAlarm.SyslogRelay.Domain.Tests.Builders;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Parsing;

public sealed class CefParserTests
{
    private readonly CefParser _unitUnderTest = new();

    [Theory]
    [InlineData("|||||||")]
    [InlineData("x")]
    [InlineData("x|x")]
    [InlineData("x|x|x|x|x|x|x")]
    [InlineData("x|x|x|x|x|x|x|x")]
    [InlineData("x|CEF:|x|x|x|x|x|x")]
    public void Parse_should_fail_when_log_has_incorrect_format(string log)
    {
        // Arrange
        var config = new ParserConfigBuilder().Build();
        _unitUnderTest.Initialise(config);

        // Act
        var result = _unitUnderTest.Parse(log);

        // Assert
        Assert.True(result.IsFailed);
        Assert.Equal("Log format is invalid.", result.ErrorMessage);
    }

    [Fact]
    public void Parse_should_fail_when_log_does_not_contain_required_value()
    {
        // Arrange
        var config = new ParserConfigBuilder()
            .WithSourceIpKeys("src")
            .WithOptional()
            .Build();
        _unitUnderTest.Initialise(config);

        // Act
        var result = _unitUnderTest.Parse("CEF:|x|x|x|x|x|x|x");

        // Assert
        Assert.True(result.IsFailed);
        Assert.Equal("Failed to parse event.", result.ErrorMessage);
    }

    [Theory]
    [MemberData(nameof(GenericCefTestLogs), MemberType = typeof(CefParserTests))]
    public void Parse_should_succeed_when_log_has_correct_format(ParserConfig config, string log, ParseResult parseResult)
    {
        // Arrange
        _unitUnderTest.Initialise(config);

        // Act
        var result = _unitUnderTest.Parse(log);

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Equal(parseResult, result.Value);
    }

    public static TheoryData<ParserConfig, string, ParseResult> GenericCefTestLogs()
    {
        var config = new ParserConfigBuilder()
            .WithSourceIpKeys("src")
            .WithDestinationIpKeys("dst")
            .WithSourcePortKeys("spt")
            .WithDestinationPortKeys("dpt")
            .WithProtocolKeys("proto")
            .WithActionKeys("act")
            .WithActionValues(["accept"], ["deny"])
            .WithOptional()
            .Build();

        return new()
        {
            {
                config,
                "CEF:0|x|x|x|x|x|x|src=x",
                new("x", null, null, null, EventProtocol.Unknown, EventAction.Unknown)
            },
            {
                config,
                "CEF:0|Fortinet|Fortigate|v6.0.3|00013|traffic:forward|3|src=192.0.2.1 dst=10.0.1.50 spt=1234 dpt=4321 proto=6 act=accept",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Allow)
            },
            {
                config,
                "CEF:0|Palo Alto Networks|PAN-OS|2.0|TRAFFIC|end|3|src=192.0.2.1 dst=10.0.1.50 spt=1234 dpt=4321 proto=6 act=deny",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Deny)
            },
        };
    }
}
