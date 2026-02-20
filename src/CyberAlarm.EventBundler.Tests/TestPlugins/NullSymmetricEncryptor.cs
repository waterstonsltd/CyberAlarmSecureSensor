using CyberAlarm.EventBundler.Plugins.Encryptors;

namespace CyberAlarm.EventBundler.Tests.TestPlugins;

public class NullSymmetricEncryptor : ISymmetricEncryptor
{
    public string AlgorithmName => "none";

    public Task EncryptStreamAsync(Stream input, Stream output, byte[] key, CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }

    public byte[] GenerateKey()
    {
        return Array.Empty<byte>();
    }
}
