using CyberAlarm.SyslogRelay.Domain.Tests.Builders;
using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Initialisation;

public sealed class InitialiseHealthCheckActivityTests
{
    private readonly InitialiseHealthCheckActivityBuilder _builder = new();

    [Fact]
    public async Task RunAsync_should_fail_when_initialising_healthchecks_fails()
    {
        // Arrange
        _builder.HealthCheckService
            .InitialiseAsync(Arg.Any<CancellationToken>())
            .Returns(Result.Fail());

        var unitUnderTest = _builder.Build();

        // Act
        var result = await unitUnderTest.RunAsync(CancellationToken.None);

        // Assert
        Assert.True(result.IsFailed);
    }

    [Fact]
    public async Task RunAsync_should_succeed_when_initialising_healthchecks_succeeds()
    {
        // Arrange
        var unitUnderTest = _builder.Build();

        // Act
        var result = await unitUnderTest.RunAsync(CancellationToken.None);

        // Assert
        Assert.True(result.IsSuccess);
        await _builder.HealthCheckService.Received(1).InitialiseAsync(Arg.Any<CancellationToken>());
    }
}
