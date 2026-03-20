using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Parsing;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Parsing;

public sealed class ParsingExtensionsTests
{
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
