using CyberAlarm.SyslogRelay.Common.EventBundler.Models;

namespace CyberAlarm.EventBundler.Services;

/// <summary>
/// Provides services for packing event data through compression and encryption.
/// </summary>
public interface IEventPackerService
{
    /// <summary>
    /// Compresses and encrypts data using the specified algorithms.
    /// </summary>
    /// <param name="serverPublicKey">The RSA public key parameters used for asymmetric encryption.</param>
    /// <param name="outputBundle">The stream to write the output bundle to.</param>
    /// <param name="data">The data to compress and encrypt.</param>
    /// <param name="bufferStream">The stream to use as a buffer during processing.</param>
    /// <param name="compressionAlgorithm">The name of the compression algorithm to use.</param>
    /// <param name="symmetricEncryptionAlgorithm">The name of the symmetric encryption algorithm to use.</param>
    /// <param name="asymmetricEncryptionAlgorithm">The name of the asymmetric encryption algorithm to use.</param>
    /// <param name="cancellationToken">A token to monitor for cancellation requests.</param>
    /// <returns>
    /// A task that represents the asynchronous operation. The task result contains an <see cref="Encryption"/> object with the encrypted data bytes and the encryption metadata.
    /// </returns>
    Task<Encryption> CompressAndEncrypt(byte[] serverPublicKey, Stream outputBundle, Stream data, Stream bufferStream, string compressionAlgorithm, string symmetricEncryptionAlgorithm, string asymmetricEncryptionAlgorithm, CancellationToken cancellationToken);

}
