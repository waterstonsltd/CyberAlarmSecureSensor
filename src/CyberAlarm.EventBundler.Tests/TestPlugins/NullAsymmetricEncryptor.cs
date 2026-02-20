using CyberAlarm.EventBundler.Plugins.Encryptors;

namespace CyberAlarm.EventBundler.Tests.TestPlugins;

public class NullAsymmetricEncryptor : IAsymmetricEncryptor
{
    public string AlgorithmName => "none";

    public byte[] EncryptSessionKey(byte[] key, byte[] unprotectedKey)
    {
        return unprotectedKey.ToArray();
    }
}
