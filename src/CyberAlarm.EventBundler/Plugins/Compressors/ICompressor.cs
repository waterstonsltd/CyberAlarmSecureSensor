using CyberAlarm.SyslogRelay.Common.EventBundler.Plugins;

namespace CyberAlarm.EventBundler.Plugins.Compressors;

/// <summary>
/// Defines a plugin interface for compression operations.
/// </summary>
public interface ICompressor : IPlugin
{
    /// <summary>
    /// Compresses the specified data asynchronously.
    /// </summary>
    /// <param name="data">The data to compress.</param>
    /// <param name="compressedData">The stream to write the compressed data to.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    public Task Compress(Stream data, Stream compressedData);
}
