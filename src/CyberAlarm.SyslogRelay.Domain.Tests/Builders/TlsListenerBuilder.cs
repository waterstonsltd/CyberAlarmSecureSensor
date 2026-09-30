using CyberAlarm.SyslogRelay.Domain.HealthCheck;
using CyberAlarm.SyslogRelay.Domain.Ingestion;
using CyberAlarm.SyslogRelay.Domain.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class TlsListenerBuilder
{
    private RelayOptions _options = new RelayOptionsBuilder().Build();

    public TlsListenerBuilder()
    {
        ApplicationManager = Substitute.For<IApplicationManager>();

        HealthToken = Substitute.For<IHealthToken>();
        HealthCheckService = Substitute.For<IHealthCheckService>();
        HealthCheckService.GetHealthToken(nameof(TlsListener)).Returns(HealthToken);

        Logger = Substitute.For<ILogger<TlsListener>>();
    }

    public IApplicationManager ApplicationManager { get; }

    public IHealthCheckService HealthCheckService { get; }

    public IHealthToken HealthToken { get; }

    public ILogger<TlsListener> Logger { get; }

    public TlsListener Build() =>
        new(ApplicationManager, HealthCheckService, Options.Create(_options), Logger);

    public TlsListenerBuilder WithOptions(RelayOptions options)
    {
        _options = options;
        return this;
    }
}