using CyberAlarm.SyslogRelay.Domain.HealthCheck;
using CyberAlarm.SyslogRelay.Domain.Tests.Builders;

namespace CyberAlarm.SyslogRelay.Domain.Tests.HealthCheck;

public sealed class HealthCheckServiceTests
{
    private readonly HealthCheckServiceBuilder _builder = new();

    [Fact]
    public void Reset_should_not_delete_healthcheck_file_when_it_does_not_exist()
    {
        // Arrange
        _builder.FileManager
            .Exists(Arg.Any<string>())
            .Returns(false);

        var unitUnderTest = _builder.Build();

        // Act
        unitUnderTest.Reset();

        // Assert
        _builder.FileManager.Received(1).Exists(Arg.Any<string>());
        _builder.FileManager.Received(0).Delete(Arg.Any<string>());
    }

    [Fact]
    public void Reset_should_delete_healthcheck_file_when_it_exists()
    {
        // Arrange
        var unitUnderTest = _builder.Build();

        // Act
        unitUnderTest.Reset();

        // Assert
        _builder.FileManager.Received(1).Exists(Arg.Any<string>());
        _builder.FileManager.Received(1).Delete(Arg.Any<string>());
    }

    [Fact]
    public void Reset_should_not_throw_when_deleting_healthcheck_file_throws()
    {
        // Arrange
        _builder.FileManager
            .When(x => x.Delete(Arg.Any<string>()))
            .Throws(new IOException());

        var unitUnderTest = _builder.Build();

        // Act
        var exception = Record.Exception(unitUnderTest.Reset);

        // Assert
        Assert.Null(exception);
    }

    [Fact]
    public async Task CheckHealthAsync_should_return_unhealthy_status_when_no_healthchecks_are_found()
    {
        // Arrange
        var unitUnderTest = _builder
            .WithHealthChecks(null)
            .Build();

        // Act
        var result = await unitUnderTest.CheckHealthAsync(CancellationToken.None);

        // Assert
        Assert.Equal(HealthStatus.Unhealthy, result.Status);
        Assert.Equal("No health checks found.", result.Reason);
    }

    [Fact]
    public async Task CheckHealthAsync_should_return_unhealthy_status_when_healthchecks_are_missing_a_registered_service()
    {
        // Arrange
        var service = Guid.NewGuid().ToString();
        var unitUnderTest = _builder
            .WithRegisteredServices([service])
            .WithHealthChecks([(Guid.NewGuid().ToString(), HealthStatus.Healthy)])
            .Build();

        // Act
        var result = await unitUnderTest.CheckHealthAsync(CancellationToken.None);

        // Assert
        Assert.Equal(HealthStatus.Unhealthy, result.Status);
        Assert.Equal($"Health check for service '{service}' not found.", result.Reason);
    }

    [Fact]
    public async Task CheckHealthAsync_should_return_unhealthy_status_when_healthchecks_contain_unhealthy_entry()
    {
        // Arrange
        var service1 = Guid.NewGuid().ToString();
        var service2 = Guid.NewGuid().ToString();

        var unitUnderTest = _builder
            .WithRegisteredServices([service1, service2])
            .WithHealthChecks([
                (service1, HealthStatus.Healthy),
                (service2, HealthStatus.Unhealthy),
            ])
            .Build();

        // Act
        var result = await unitUnderTest.CheckHealthAsync(CancellationToken.None);

        // Assert
        Assert.Equal(HealthStatus.Unhealthy, result.Status);
        Assert.Equal($"Service '{service2}' is unhealthy.", result.Reason);
    }

    [Fact]
    public async Task CheckHealthAsync_should_return_healthy_status_when_all_healthchecks_are_healthy()
    {
        // Arrange
        var service1 = Guid.NewGuid().ToString();
        var service2 = Guid.NewGuid().ToString();

        var unitUnderTest = _builder
            .WithRegisteredServices([service1, service2])
            .WithHealthChecks([
                (service1, HealthStatus.Healthy),
                (service2, HealthStatus.Healthy),
            ])
            .Build();

        // Act
        var result = await unitUnderTest.CheckHealthAsync(CancellationToken.None);

        // Assert
        Assert.Equal(HealthStatus.Healthy, result.Status);
        Assert.Equal("All services are healthy.", result.Reason);
    }

    [Fact]
    public async Task SetHealthyAsync_should_throw_when_service_is_not_registered()
    {
        // Arrange
        var service = Guid.NewGuid().ToString();
        var unitUnderTest = _builder.Build();

        // Act & Assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await unitUnderTest.SetHealthyAsync(service, CancellationToken.None));

        Assert.Equal($"Service '{service}' is not registered.", exception.Message);
    }

    [Fact]
    public async Task SetHealthyAsync_should_persist_healthy_status_for_the_service()
    {
        // Arrange
        var service = Guid.NewGuid().ToString();
        var unitUnderTest = _builder
            .WithRegisteredServices([service])
            .Build();

        // Act
        await unitUnderTest.SetHealthyAsync(service, CancellationToken.None);

        // Assert
        await _builder.FileManager.Received(1).SerialiseToFileAsync<Dictionary<string, HealthCheckEntry>>(
            Arg.Is<Dictionary<string, HealthCheckEntry>>(x =>
                x.ContainsKey(service) &&
                x[service].Status == HealthStatus.Healthy),
            Arg.Any<string>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task SetUnhealthyAsync_should_throw_when_service_is_not_registered()
    {
        // Arrange
        var service = Guid.NewGuid().ToString();
        var unitUnderTest = _builder.Build();

        // Act & Assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await unitUnderTest.SetUnhealthyAsync(service, CancellationToken.None));

        Assert.Equal($"Service '{service}' is not registered.", exception.Message);
    }

    [Fact]
    public async Task SetUnhealthyAsync_should_persist_unhealthy_status_for_the_service()
    {
        // Arrange
        var service = Guid.NewGuid().ToString();
        var unitUnderTest = _builder
            .WithRegisteredServices([service])
            .Build();

        // Act
        await unitUnderTest.SetUnhealthyAsync(service, CancellationToken.None);

        // Assert
        await _builder.FileManager.Received(1).SerialiseToFileAsync<Dictionary<string, HealthCheckEntry>>(
            Arg.Is<Dictionary<string, HealthCheckEntry>>(x =>
                x.ContainsKey(service) &&
                x[service].Status == HealthStatus.Unhealthy),
            Arg.Any<string>(),
            Arg.Any<CancellationToken>());
    }
}
