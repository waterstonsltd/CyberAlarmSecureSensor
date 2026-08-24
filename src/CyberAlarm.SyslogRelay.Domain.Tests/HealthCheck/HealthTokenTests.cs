using CyberAlarm.SyslogRelay.Domain.HealthCheck;
using CyberAlarm.SyslogRelay.Domain.Tests.Builders;
using HealthChecks = System.Collections.Generic.Dictionary<string, CyberAlarm.SyslogRelay.Domain.HealthCheck.HealthCheckEntry?>;

namespace CyberAlarm.SyslogRelay.Domain.Tests.HealthCheck;

public sealed class HealthTokenTests
{
    private readonly HealthCheckServiceBuilder _builder = new();

    [Fact]
    public async Task HealthyAsync_should_throw_when_service_is_not_registered()
    {
        // Arrange
        var service = Guid.NewGuid().ToString();
        var healthCheckService = _builder.Build();
        var unitUnderTest = healthCheckService.GetHealthToken(service);

        // Act & Assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await unitUnderTest.HealthyAsync(CancellationToken.None));

        Assert.Equal($"Service '{service}' is not registered.", exception.Message);
    }

    [Fact]
    public async Task HealthyAsync_should_persist_healthy_status_for_the_service()
    {
        // Arrange
        var service = Guid.NewGuid().ToString();
        var healthCheckService = _builder
            .WithHealthChecks([(service, null)])
            .Build();
        var unitUnderTest = healthCheckService.GetHealthToken(service);

        // Act
        await unitUnderTest.HealthyAsync(CancellationToken.None);

        // Assert
        await _builder.FileManager.Received(1).SerialiseToFileAsync(
            Arg.Is<HealthChecks>(x =>
                x.ContainsKey(service) &&
                x[service] != null &&
                x[service]!.Status == HealthStatus.Healthy),
            Arg.Any<string>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task UnhealthyAsync_should_throw_when_service_is_not_registered()
    {
        // Arrange
        var service = Guid.NewGuid().ToString();
        var healthCheckService = _builder.Build();
        var unitUnderTest = healthCheckService.GetHealthToken(service);

        // Act & Assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await unitUnderTest.UnhealthyAsync(CancellationToken.None));

        Assert.Equal($"Service '{service}' is not registered.", exception.Message);
    }

    [Fact]
    public async Task SetUnhealthyAsync_should_persist_unhealthy_status_for_the_service()
    {
        // Arrange
        var service = Guid.NewGuid().ToString();
        var healthCheckService = _builder
            .WithHealthChecks([(service, null)])
            .Build();
        var unitUnderTest = healthCheckService.GetHealthToken(service);

        // Act
        await unitUnderTest.UnhealthyAsync(CancellationToken.None);

        // Assert
        await _builder.FileManager.Received(1).SerialiseToFileAsync(
            Arg.Is<HealthChecks>(x =>
                x.ContainsKey(service) &&
                x[service] != null &&
                x[service]!.Status == HealthStatus.Unhealthy),
            Arg.Any<string>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task UnregisterAsync_should_remove_service_from_persisted_healthchecks()
    {
        // Arrange
        var service = Guid.NewGuid().ToString();
        var healthCheckService = _builder
            .WithHealthChecks([
                (service, null),
                (Guid.NewGuid().ToString(), null),
            ])
            .Build();
        var unitUnderTest = healthCheckService.GetHealthToken(service);

        // Act
        await unitUnderTest.UnregisterAsync(CancellationToken.None);

        // Assert
        await _builder.FileManager.Received(1).SerialiseToFileAsync(
            Arg.Is<HealthChecks>(x => x.Count == 1 && !x.ContainsKey(service)),
            Arg.Any<string>(),
            Arg.Any<CancellationToken>());
    }
}
