using CyberAlarm.SyslogRelay.Domain.HealthCheck;
using CyberAlarm.SyslogRelay.Domain.Ingestion;
using CyberAlarm.SyslogRelay.Domain.Services;
using CyberAlarm.SyslogRelay.Domain.Tests.Builders;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Ingestion;

public sealed class TcpListenerTests
{
    [Fact]
    public async Task StartAsync_should_unregister_health_check_when_tls_is_enabled_and_plaintext_override_is_not_set()
    {
        var applicationManager = Substitute.For<IApplicationManager>();
        var healthToken = Substitute.For<IHealthToken>();
        var healthCheckService = Substitute.For<IHealthCheckService>();
        healthCheckService.GetHealthToken(nameof(TcpListener)).Returns(healthToken);
        var logger = Substitute.For<ILogger<TcpListener>>();

        var options = new RelayOptionsBuilder()
            .WithTlsEnabled(true)
            .WithAllowPlaintextListenersWhenTlsEnabled(false)
            .Build();

        var unitUnderTest = new TcpListener(applicationManager, healthCheckService, Options.Create(options), logger);

        await unitUnderTest.StartAsync((syslogEvent, cancellationToken) => Task.CompletedTask, CancellationToken.None);

        await healthToken.Received(1).UnregisterAsync(Arg.Any<CancellationToken>());
        await healthToken.DidNotReceive().HealthyAsync(Arg.Any<CancellationToken>());
        applicationManager.DidNotReceive().StopApplication();
    }
}