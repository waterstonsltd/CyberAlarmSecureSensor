using CyberAlarm.EventBundler.Plugins.Compressors;
using CyberAlarm.EventBundler.Plugins.Encryptors;
using CyberAlarm.EventBundler.Services;
using CyberAlarm.SyslogRelay.Common.EventBundler.Plugins;
using NSubstitute;

namespace CyberAlarm.EventBundler.Tests;

public class EventPackerServiceBuilder
{
    public IPluginFactory<ICompressor> CompressorFactory { get; set; }
    public IPluginFactory<IAsymmetricEncryptor> AsymmetricEncryptorFactory { get; set; }
    public IPluginFactory<ISymmetricEncryptor> SymmetricEncryptorFactory { get; set; }

    public EventPackerServiceBuilder()
    {
        CompressorFactory = Substitute.For<IPluginFactory<ICompressor>>();
        AsymmetricEncryptorFactory = Substitute.For<IPluginFactory<IAsymmetricEncryptor>>();
        SymmetricEncryptorFactory = Substitute.For<IPluginFactory<ISymmetricEncryptor>>();
    }

    public EventPackerServiceBuilder WithCompressorFactory(IPluginFactory<ICompressor> compressorFactory)
    {
        CompressorFactory = compressorFactory;
        return this;
    }

    public EventPackerServiceBuilder WithAsymmetricEncryptorFactory(IPluginFactory<IAsymmetricEncryptor> asymmetricEncryptorFactory)
    {
        AsymmetricEncryptorFactory = asymmetricEncryptorFactory;
        return this;
    }

    public EventPackerServiceBuilder WithSymmetricEncryptorFactory(IPluginFactory<ISymmetricEncryptor> symmetricEncryptorFactory)
    {
        SymmetricEncryptorFactory = symmetricEncryptorFactory;
        return this;
    }

    public EventPackerServiceBuilder WithDefaultCompressor(string algorithmName = "default")
    {
        var compressor = Substitute.For<ICompressor>();
        CompressorFactory.CreatePlugin(algorithmName).Returns(compressor);
        return this;
    }

    public EventPackerServiceBuilder WithDefaultSymmetricEncryptor(string algorithmName = "default")
    {
        var encryptor = Substitute.For<ISymmetricEncryptor>();
        SymmetricEncryptorFactory.CreatePlugin(algorithmName).Returns(encryptor);
        return this;
    }

    public EventPackerServiceBuilder WithDefaultAsymmetricEncryptor(string algorithmName = "default")
    {
        var encryptor = Substitute.For<IAsymmetricEncryptor>();
        AsymmetricEncryptorFactory.CreatePlugin(algorithmName).Returns(encryptor);
        return this;
    }

    public EventPackerService Build()
    {
        return new EventPackerService(CompressorFactory, AsymmetricEncryptorFactory, SymmetricEncryptorFactory);
    }
}
