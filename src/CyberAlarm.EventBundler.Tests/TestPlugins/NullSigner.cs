using CyberAlarm.EventBundler.Plugins.Signers;

namespace CyberAlarm.EventBundler.Tests.TestPlugins;

internal sealed class NullSigner : ISigner
{
    public string AlgorithmName => "none";

    public ushort SignatureSize => 0;

    public byte[] Sign(byte[] key, Stream data)
    {
        return Array.Empty<byte>();
    }
}
