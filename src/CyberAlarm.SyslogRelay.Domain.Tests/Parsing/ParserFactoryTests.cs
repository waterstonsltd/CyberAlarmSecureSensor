using CyberAlarm.SyslogRelay.Domain.Parsing;
using CyberAlarm.SyslogRelay.Domain.Tests.Builders;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Parsing;

public sealed class ParserFactoryTests
{
    private readonly ParserFactoryBuilder _builder = new();

    [Fact]
    public void Create_should_throw_when_parser_name_is_empty()
    {
        // Arrange
        var unitUnderTest = _builder.Build();

        // Act & Assert
        Assert.Throws<ArgumentException>(() => unitUnderTest.Create(string.Empty, null));
    }

    [Fact]
    public void Create_should_return_null_when_no_parser_found()
    {
        // Arrange
        var unitUnderTest = _builder
            .WithParser(null)
            .Build();

        // Act
        var result = unitUnderTest.Create("x", null);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public void Create_should_return_parser_based_on_parser_name()
    {
        // Arrange
        var name = nameof(NullParser);
        var unitUnderTest = _builder
            .WithParser(new NullParser())
            .Build();

        // Act
        var parser = unitUnderTest.Create(name, null);

        // Assert
        Assert.Equal(name, parser?.GetType().Name);
    }
}
