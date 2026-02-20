using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.Parsing.Fortigate;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Parsing;

public sealed class FortigateParserTests
{
    private readonly FortigateParser _unitUnderTest = new();

    [Fact]
    public void Name_should_return_class_name()
    {
        // Act & Assert
        Assert.Equal(nameof(FortigateParser), _unitUnderTest.Name);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Parse_should_throw_when_log_is_empty(string? log)
    {
        // Act & Assert
        Assert.ThrowsAny<ArgumentException>(() => _unitUnderTest.Parse(log!));
    }

    [Fact]
    public void Parse_should_fail_when_log_has_incorrect_format()
    {
        // Act
        var result = _unitUnderTest.Parse(Guid.NewGuid().ToString());

        // Assert
        Assert.True(result.IsFailed);
        Assert.Equal("Log format is invalid.", result.ErrorMessage);
    }

    [Theory]
    [InlineData("x=1")]
    public void Parse_should_fail_when_log_cannot_be_parsed(string log)
    {
        // Act
        var result = _unitUnderTest.Parse(log);

        // Assert
        Assert.True(result.IsFailed);
        Assert.Equal("Failed to parse event.", result.ErrorMessage);
    }

    [Theory]
    [MemberData(nameof(TestLogs), MemberType = typeof(FortigateParserTests))]
    public void Parse_should_succeed_when_log_has_correct_format(string log, ParseResult parseResult)
    {
        // Act
        var result = _unitUnderTest.Parse(log);

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Equal(parseResult, result.Value);
    }

    public static TheoryData<string, ParseResult> TestLogs =>
        new()
        {
            {
                "x srcip=192.0.2.1 srcport=1234 dstip=10.0.1.50 dstport=4321 proto=6 action=\"close\" x",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Allow)
            },
        };
}
