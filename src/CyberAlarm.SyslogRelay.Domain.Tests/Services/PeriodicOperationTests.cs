using CyberAlarm.SyslogRelay.Domain.Tests.Builders;
using CyberAlarm.SyslogRelay.Tests.Common;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Services;

public sealed class PeriodicOperationTests
{
    private readonly PeriodicOperationBuilder _builder = new();

    [Fact]
    public void Start_should_throw_when_settings_is_null()
    {
        // Arrange
        var unitUnderTest = _builder.Build();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => unitUnderTest.Start(default, CancellationToken.None));
    }

    [Fact]
    public void Start_should_throw_when_operation_in_settings_is_null()
    {
        // Arrange
        var settingsBuilder = new PeriodicOperationSettingsBuilder()
            .WithOperation(default);

        var unitUnderTest = _builder.Build();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => unitUnderTest.Start(settingsBuilder.Build(), CancellationToken.None));
    }

    [Fact]
    public async Task StopAsync_should_cancel_operation()
    {
        // Arrange
        var settingsBuilder = new PeriodicOperationSettingsBuilder();

        var unitUnderTest = _builder.Build();
        unitUnderTest.Start(settingsBuilder.Build(), CancellationToken.None);

        // Act
        await unitUnderTest.StopAsync();

        // Assert
        Assert.Contains((LogLevel.Debug, $"Periodic {settingsBuilder.OperationDescription} cancelled."), _builder.Logger.ReceivedLogs());
    }
}
