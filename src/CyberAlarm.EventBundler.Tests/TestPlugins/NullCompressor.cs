using CyberAlarm.EventBundler.Plugins.Compressors;

namespace CyberAlarm.EventBundler.Tests.TestPlugins;

internal sealed class NullCompressor : ICompressor
{
    public string AlgorithmName => "none";

    public Task Compress(Stream data, Stream compressedData)
    {
        return Task.CompletedTask;
    }
}
