using CyberAlarm.SyslogRelay.Domain.Parsing.Cisco;
using CyberAlarm.SyslogRelay.Domain.Tests.Builders;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Parsing;

public sealed class ParserFactoryTests
{
    private readonly ParserFactoryBuilder _builder = new();

    [Fact]
    public async Task Create_should_throw_when_parser_name_is_empty()
    {
        // Arrange
        var unitUnderTest = _builder.Build();

        // Act & Assert
        Assert.Throws<ArgumentException>(() => unitUnderTest.Create(string.Empty));
    }

    [Fact]
    public async Task Create_should_return_null_when_no_parser_found()
    {
        // Arrange
        var unitUnderTest = _builder.Build();

        // Act
        var result = unitUnderTest.Create("x");

        // Assert
        Assert.Null(result);
    }

    [Theory]
    [InlineData(nameof(CiscoAsaParser))]
    public async Task Create_should_return_parser_based_on_parser_name(string parserName)
    {
        // Arrange
        var unitUnderTest = _builder
            .WithParsers([new CiscoAsaParser()])
            .Build();

        // Act
        var parser = unitUnderTest.Create(parserName);

        // Assert
        Assert.Equal(parserName, parser?.Name);
    }
}
