using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.HealthCheck;
using CyberAlarm.SyslogRelay.Domain.Tests.Builders;
using HealthChecks = System.Collections.Generic.Dictionary<string, CyberAlarm.SyslogRelay.Domain.HealthCheck.HealthCheckEntry?>;

namespace CyberAlarm.SyslogRelay.Domain.Tests.HealthCheck;

public sealed class HealthCheckServiceTests
{
    private readonly HealthCheckServiceBuilder _builder = new();

    [Fact]
    public async Task InitialiseAsync_should_not_persist_healthchecks_and_succeed_when_there_are_no_services_to_register()
    {
        // Arrange
        var unitUnderTest = _builder.Build();

        // Act
        var result = await unitUnderTest.InitialiseAsync(CancellationToken.None);

        // Assert
        Assert.True(result.IsSuccess);
        await _builder.FileManager.Received(0).SerialiseToFileAsync(Arg.Any<HealthChecks>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task InitialiseAsync_should_persist_healthchecks_and_succeed_when_there_are_services_to_register()
    {
        // Arrange
        var service = Guid.NewGuid().ToString();
        var unitUnderTest = _builder
            .WithRegisteredServices([service])
            .Build();

        // Act
        var result = await unitUnderTest.InitialiseAsync(CancellationToken.None);

        // Assert
        Assert.True(result.IsSuccess);
        await _builder.FileManager.Received(1).SerialiseToFileAsync(
            Arg.Is<HealthChecks>(x => x.Count == 1 && x.ContainsKey(service) && x[service] == null),
            Arg.Any<string>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task InitialiseAsync_should_fail_and_not_throw_when_persisting_healthchecks_throws()
    {
        // Arrange
        _builder.FileManager
            .When(x => x.SerialiseToFileAsync(Arg.Any<HealthChecks>(), Arg.Any<string>(), Arg.Any<CancellationToken>()))
            .Throws(new IOException());

        var unitUnderTest = _builder
            .WithRegisteredServices([Guid.NewGuid().ToString()])
            .Build();

        // Act
        var result = await unitUnderTest.InitialiseAsync(CancellationToken.None);

        // Assert
        Assert.True(result.IsFailed);
        Assert.StartsWith("Failed to initialise health checks: ", result.ErrorMessage);
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
            .WithHealthChecks([(service, null)])
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
        var service = Guid.NewGuid().ToString();
        var unitUnderTest = _builder
            .WithHealthChecks([
                (Guid.NewGuid().ToString(), HealthStatus.Healthy),
                (service, HealthStatus.Unhealthy),
            ])
            .Build();

        // Act
        var result = await unitUnderTest.CheckHealthAsync(CancellationToken.None);

        // Assert
        Assert.Equal(HealthStatus.Unhealthy, result.Status);
        Assert.Equal($"Service '{service}' is unhealthy.", result.Reason);
    }

    [Fact]
    public async Task CheckHealthAsync_should_return_healthy_status_when_all_healthchecks_are_healthy()
    {
        // Arrange
        var unitUnderTest = _builder
            .WithHealthChecks([
                (Guid.NewGuid().ToString(), HealthStatus.Healthy),
                (Guid.NewGuid().ToString(), HealthStatus.Healthy),
            ])
            .Build();

        // Act
        var result = await unitUnderTest.CheckHealthAsync(CancellationToken.None);

        // Assert
        Assert.Equal(HealthStatus.Healthy, result.Status);
        Assert.Equal("All services are healthy.", result.Reason);
    }
}
