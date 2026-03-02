using CyberAlarm.SyslogRelay.Domain.Tests.Builders;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Initialisation;

public sealed class ResetHealthCheckActivityTests
{
    private readonly ResetHealthCheckActivityBuilder _builder = new();

    [Fact]
    public async Task RunAsync_should_reset_health_check()
    {
        // Arrange
        var unitUnderTest = _builder.Build();

        // Act
        var result = await unitUnderTest.RunAsync(CancellationToken.None);

        // Assert
        Assert.True(result.IsSuccess);
        _builder.HealthCheckService.Received(1).Reset();
    }
}
