using CyberAlarm.SyslogRelay.Domain.HealthCheck;
using CyberAlarm.SyslogRelay.Domain.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class HealthCheckServiceBuilder
{
    private readonly HealthCheckOptions _options = new();

    public HealthCheckServiceBuilder()
    {
        FileManager = Substitute.For<IFileManager>();
        Logger = Substitute.For<ILogger<HealthCheckService>>();
    }

    public IFileManager FileManager { get; }

    public ILogger<HealthCheckService> Logger { get; }

    public HealthCheckService Build() => new(FileManager, Options.Create(_options), Logger);

    public HealthCheckServiceBuilder WithRegisteredServices(string[] services)
    {
        _options.ServicesToRegister = services;
        return this;
    }

    public HealthCheckServiceBuilder WithHealthChecks(IEnumerable<(string Service, HealthStatus? Status)>? healthChecks)
    {
        FileManager
            .DeserialiseFromFileAsync<Dictionary<string, HealthCheckEntry?>>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(healthChecks?.ToDictionary(x => x.Service, x => x.Status.HasValue ? new HealthCheckEntry(DateTime.UtcNow, x.Status.Value) : null));

        return this;
    }
}
