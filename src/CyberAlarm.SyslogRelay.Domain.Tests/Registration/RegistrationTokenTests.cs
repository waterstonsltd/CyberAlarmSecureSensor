using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.Registration;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Registration;

public sealed class RegistrationTokenTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Validate_should_fail_when_empty_value_is_provided(string? value)
    {
        // Act
        var result = RegistrationToken.Validate(value);

        // Assert
        Assert.True(result.IsFailed);
        Assert.Equal("Registration token is missing.", result.ErrorMessage);
    }

    [Theory]
    [InlineData("x")]
    [InlineData("x.x")]
    [InlineData("x.x.x")]
    [InlineData("1.x")]
    public void Validate_should_fail_when_invalid_value_is_provided(string value)
    {
        // Act
        var result = RegistrationToken.Validate(value);

        // Assert
        Assert.True(result.IsFailed);
        Assert.Equal("Registration token is invalid.", result.ErrorMessage);
    }

    [Theory]
    [InlineData("1..")]
    [InlineData("1x..")]
    [InlineData("1.x.x")]
    public void Validate_should_succeed_when_valid_value_is_provided(string value)
    {
        // Act
        var result = RegistrationToken.Validate(value);

        // Assert
        Assert.True(result.IsSuccess);
    }
}
