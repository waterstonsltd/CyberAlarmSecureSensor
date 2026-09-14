using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Common.Models.ParserConfiguration;
using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.Parsing.LinuxNetfilter;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Parsing;

public sealed class SmoothwallParserTests
{
    private readonly LinuxNetfilterParser _unitUnderTest = new();

    [Theory]
    [InlineData("x")]
    [InlineData("x=1")]
    [InlineData("kernel: x=1")]
    [InlineData("kernel: X_")]
    [InlineData("kernel: X x=1")]
    public void Parse_should_fail_when_log_has_incorrect_format(string log)
    {
        // Arrange
        var config = BuildConfig();
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
        var config = BuildConfig(sourceIpKeys: ["src"]);
        _unitUnderTest.Initialise(config);

        // Act
        var result = _unitUnderTest.Parse("x kernel: X_x");

        // Assert
        Assert.True(result.IsFailed);
        Assert.Equal("Failed to parse event.", result.ErrorMessage);
    }

    [Theory]
    [MemberData(nameof(SmoothwallTestLogs), MemberType = typeof(SmoothwallParserTests))]
    public void Parse_should_succeed_when_log_has_correct_format(LinuxNetfilterParserConfig config, string log, ParseResult parseResult)
    {
        // Arrange
        _unitUnderTest.Initialise(config);

        // Act
        var result = _unitUnderTest.Parse(log);

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Equal(parseResult, result.Value);
    }

    public static TheoryData<LinuxNetfilterParserConfig, string, ParseResult> SmoothwallTestLogs()
    {
        var config = BuildConfig(allowActionValues: ["ACCEPT"]);

        return new()
        {
            {
                config,
                "x kernel: X_x SRC=x",
                new("x", null, null, null, EventProtocol.Unknown, EventAction.Unknown)
            },
            {
                config,
                "x smoothwall kernel: ACCEPT_FORWARD IN=green0 OUT=red0 SRC=192.0.2.1 DST=10.0.1.50 PROTO=TCP SPT=1234 DPT=4321 x",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Allow)
            },
        };
    }

    private static LinuxNetfilterParserConfig BuildConfig(
        string[]? sourceIpKeys = null,
        string[]? destinationIpKeys = null,
        string[]? sourcePortKeys = null,
        string[]? destinationPortKeys = null,
        string[]? protocolKeys = null,
        string[]? allowActionValues = null)
    {
        return new LinuxNetfilterParserConfig
        {
            SourceIpKeys = sourceIpKeys ?? ["SRC"],
            DestinationIpKeys = destinationIpKeys ?? ["DST"],
            SourcePortKeys = sourcePortKeys ?? ["SPT"],
            DestinationPortKeys = destinationPortKeys ?? ["DPT"],
            ProtocolKeys = protocolKeys ?? ["PROTO"],
            ActionKeys = [],
            IsDestinationIpOptional = true,
            IsSourcePortOptional = true,
            IsDestinationPortOptional = true,
            IsProtocolOptional = true,
            AllowActionValues = allowActionValues ?? [],
            DenyActionValues = [],
            ActionExtractRegex = @"kernel:\s+([A-Z]+)_.",
            ActionCaptureGroup = 1,
        };
    }
}
