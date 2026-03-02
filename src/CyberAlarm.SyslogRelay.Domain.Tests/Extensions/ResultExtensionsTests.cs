using CyberAlarm.SyslogRelay.Domain.Extensions;
using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Extensions;

public sealed class ResultExtensionsTests
{
    [Fact]
    public void ErrorMessage_should_throw_when_Result_contains_more_than_one_error()
    {
        // Act & Assert
        Assert.Throws<InvalidOperationException>(() =>
            Result.Fail(["x", "x"]).ErrorMessage);
    }

    [Fact]
    public void ErrorMessage_should_return_error_message()
    {
        // Act
        var result = Result.Fail("x").ErrorMessage;

        // Assert
        Assert.Equal("x", result);
    }
}
