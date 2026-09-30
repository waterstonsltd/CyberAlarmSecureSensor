using CyberAlarm.EventBundler.Plugins.Signers;
using CyberAlarm.EventBundler.Services;
using CyberAlarm.SyslogRelay.Common.EventBundler.Plugins;
using Microsoft.Extensions.Logging;
using NSubstitute;

namespace CyberAlarm.EventBundler.Tests.Builders;

internal sealed class EventBundlerServiceBuilder
{
    public EventBundlerServiceBuilder()
    {
        SignerFactory = Substitute.For<IPluginFactory<ISigner>>();
        EventPackerService = Substitute.For<IEventPackerService>();
        Logger = Substitute.For<ILogger<EventBundlerService>>();
        DefaultSigner = Substitute.For<ISigner>();
        DefaultSigner.AlgorithmName.Returns("TestSigner");
        SignerFactory.CreatePlugin(Arg.Any<string>()).Returns(DefaultSigner);
    }

    public IPluginFactory<ISigner> SignerFactory { get; }

    public ISigner DefaultSigner { get; }

    public IEventPackerService EventPackerService { get; }

    public ILogger<EventBundlerService> Logger { get; set; }

    public EventBundlerService Build()
    {
        return new EventBundlerService(SignerFactory, EventPackerService, Logger);
    }
}
