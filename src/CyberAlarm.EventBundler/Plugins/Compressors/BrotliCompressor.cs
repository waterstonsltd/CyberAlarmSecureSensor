using System.IO.Compression;
using CyberAlarm.SyslogRelay.Common.EventBundler.Settings;

namespace CyberAlarm.EventBundler.Plugins.Compressors;

/// <summary>
/// Provides Brotli compression functionality for event data.
/// </summary>
/// <remarks>
/// This compressor uses the Brotli algorithm with optimal compression level to achieve
/// high compression ratios suitable for network transmission and storage of event bundles.
/// </remarks>
public class BrotliCompressor : ICompressor
{
    /// <summary>
    /// Gets the name of the compression algorithm.
    /// </summary>
    /// <value>
    /// Returns "Brotli" as the algorithm identifier.
    /// </value>
    public string AlgorithmName => SupportedAlgorithms.Compressors.Brotli;

    /// <summary>
    /// Compresses the specified byte array using the Brotli compression algorithm.
    /// </summary>
    /// <param name="data">The uncompressed byte array to compress.</param>
    /// <param name="compressedData">The stream to write the compressed data to.</param>
    /// <returns>
    /// A task that represents the asynchronous operation.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="dataBytes"/> is null.
    /// </exception>
    public async Task Compress(Stream data, Stream compressedData)
    {
        await using (var brotliStream = new BrotliStream(compressedData, CompressionLevel.Optimal, leaveOpen: true))
        {
            await data.CopyToAsync(brotliStream);
        }

        compressedData.Position = 0;
    }
}
