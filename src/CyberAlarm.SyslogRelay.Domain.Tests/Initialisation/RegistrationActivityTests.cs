using CyberAlarm.SyslogRelay.Domain.Tests;
using CyberAlarm.SyslogRelay.Domain.Tests.Builders;
using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Initialisation;

public sealed class RegistrationActivityTests
{
    private readonly RegistrationActivityBuilder _builder = new();

    [Fact]
    public async Task RunAsync_should_fail_when_registration_fails()
    {
        // Arrange
        _builder.RegistrationService
            .RegisterAsync(Arg.Any<CancellationToken>())
            .Returns(Result.Fail());

        var unitUnderTest = _builder.Build();

        // Act
        var result = await unitUnderTest.RunAsync(CancellationToken.None);

        // Assert
        Assert.True(result.IsFailed);
    }

    [Fact]
    public async Task RunAsync_should_succeed_when_registration_succeeds()
    {
        // Arrange
        var unitUnderTest = _builder.Build();

        // Act
        var result = await unitUnderTest.RunAsync(CancellationToken.None);

        // Assert
        Assert.True(result.IsSuccess);
    }
}
