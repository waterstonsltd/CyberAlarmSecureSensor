using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.Parsing;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Parsing;

public sealed class NullParserTests
{
    private readonly NullParser _unitUnderTest = new();

    [Fact]
    public void Parse_should_always_fail()
    {
        // Act
        var result = _unitUnderTest.Parse(Guid.NewGuid().ToString());

        // Assert
        Assert.True(result.IsFailed);
        Assert.Equal($"{nameof(NullParser)} does not parse any logs.", result.ErrorMessage);
    }
}
