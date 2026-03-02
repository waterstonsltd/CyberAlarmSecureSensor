using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Parsing;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Parsing;

public sealed class ParsingExtensionsTests
{
    [Fact]
    public void ParseKeyValues_should_return_null_when_no_key_value_matches_found()
    {
        // Act
        var result = "x".ParseKeyValues();

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public void ParseKeyValues_should_return_dictionary_with_parsed_key_value_pairs()
    {
        // Act
        var result = "x=1 y=\"2\"    z=3".ParseKeyValues();

        // Assert
        Assert.NotNull(result);
        Assert.Equal(3, result.Count);
        Assert.Equal("1", result["x"]);
        Assert.Equal("2", result["y"]);
        Assert.Equal("3", result["z"]);
    }

    [Theory]
    [InlineData("", EventProtocol.Unknown)]
    [InlineData("x", EventProtocol.Unknown)]
    [InlineData("-1", EventProtocol.Unknown)]
    [InlineData("1", EventProtocol.Icmp)]
    [InlineData("icmp", EventProtocol.Icmp)]
    [InlineData("ICMP", EventProtocol.Icmp)]
    public void ToProtocol_should_return_protocol_enum(string value, EventProtocol expected)
    {
        // Act
        var result = value.ToProtocol();

        // Assert
        Assert.Equal(expected, result);
    }
}
