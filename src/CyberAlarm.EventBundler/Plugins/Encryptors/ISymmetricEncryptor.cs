using CyberAlarm.SyslogRelay.Common.EventBundler.Plugins;

namespace CyberAlarm.EventBundler.Plugins.Encryptors;

/// <summary>
/// Defines a symmetric encryption plugin that provides methods for generating encryption keys,
/// and encrypting data using symmetric cryptographic algorithms.
/// </summary>
public interface ISymmetricEncryptor : IPlugin
{
    /// <summary>
    /// Generates a new cryptographically secure symmetric encryption key.
    /// </summary>
    /// <returns>A byte array containing the generated symmetric key.</returns>
    byte[] GenerateKey();

    /// <summary>
    /// Encrypts data from the input stream and writes the encrypted result to the output stream using asymmetric encryption.
    /// </summary>
    /// <param name="input">The input stream containing the data to encrypt.</param>
    /// <param name="output">The output stream where the encrypted data will be written.</param>
    /// <param name="key">The asymmetric encryption key used to encrypt the data.</param>
    /// <param name="cancellationToken">A cancellation token that can be used to cancel the encryption operation.</param>
    /// <returns>A byte array containing encryption metadata or additional information produced during the encryption process.</returns>
    Task EncryptStreamAsync(
        Stream input,
        Stream output,
        byte[] key,
        CancellationToken cancellationToken);
}
