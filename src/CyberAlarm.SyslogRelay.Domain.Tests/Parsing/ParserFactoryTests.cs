using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Parsing;
using CyberAlarm.SyslogRelay.Domain.Parsing.Cisco;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Parsing;

public sealed class ParserFactoryTests
{
    [Fact]
    public async Task Create_should_throw_when_pattern_is_not_supported()
    {
        // Arrange
        var pattern = EventPattern.Unknown;
        var unitUnderTest = new ParserFactory([]);

        // Act & Assert
        var exception = Assert.Throws<NotSupportedException>(() => unitUnderTest.Create(pattern));
        Assert.Equal($"Parsing for '{pattern}' not supported.", exception.Message);
    }

    [Fact]
    public async Task Create_should_throw_when_no_parser_found_for_given_pattern()
    {
        // Arrange
        var pattern = EventPattern.CiscoAsa;
        var unitUnderTest = new ParserFactory([]);

        // Act & Assert
        var exception = Assert.Throws<InvalidOperationException>(() => unitUnderTest.Create(pattern));
        Assert.Equal($"No parser found for '{pattern}'.", exception.Message);
    }

    [Theory]
    [InlineData(EventPattern.CiscoAsa, nameof(CiscoAsaParser))]
    public async Task Create_should_return_parser_based_on_given_pattern(EventPattern pattern, string parserName)
    {
        // Arrange
        var unitUnderTest = new ParserFactory([new CiscoAsaParser()]);

        // Act
        var parser = unitUnderTest.Create(pattern);

        // Assert
        Assert.Equal(parserName, parser.Name);
    }
}
