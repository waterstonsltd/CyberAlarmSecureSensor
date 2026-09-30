using CyberAlarm.SyslogRelay.Domain.Initialisation;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class CheckConfigurationActivityBuilder
{
    private RelayOptions _options = new RelayOptionsBuilder().Build();

    public CheckConfigurationActivityBuilder()
    {
        Logger = Substitute.For<ILogger<CheckConfigurationActivity>>();
    }

    public ILogger<CheckConfigurationActivity> Logger { get; }

    public CheckConfigurationActivity Build() =>
        new(Options.Create(_options), Logger);

    public CheckConfigurationActivityBuilder WithOptions(RelayOptions options)
    {
        _options = options;
        return this;
    }
}
