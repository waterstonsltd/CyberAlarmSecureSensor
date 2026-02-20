using System.Security.Cryptography;
using CyberAlarm.EventBundler.Plugins.Compressors;
using CyberAlarm.EventBundler.Plugins.Encryptors;
using CyberAlarm.SyslogRelay.Common.EventBundler.Models;
using CyberAlarm.SyslogRelay.Common.EventBundler.Plugins;

namespace CyberAlarm.EventBundler.Services;

/// <summary>
/// Service responsible for compressing, encrypting, decrypting, and decompressing event data
/// using configurable compression and encryption algorithms via plugin factories.
/// </summary>
public sealed class EventPackerService : IEventPackerService
{
    private readonly IPluginFactory<ICompressor> _compressorFactory;
    private readonly IPluginFactory<IAsymmetricEncryptor> _asymmetricEncryptorFactory;
    private readonly IPluginFactory<ISymmetricEncryptor> _symmetricEncryptorFactory;

    /// <summary>
    /// Initializes a new instance of the <see cref="EventPackerService"/> class.
    /// </summary>
    /// <param name="compressorFactory">The factory for creating compression plugins.</param>
    /// <param name="asymmetricEncryptorFactory">The factory for creating asymmetric encryption plugins.</param>
    /// <param name="symmetricEncryptorFactory">The factory for creating symmetric encryption plugins.</param>
    /// <exception cref="ArgumentNullException">Thrown when any factory parameter is null.</exception>
    public EventPackerService(IPluginFactory<ICompressor> compressorFactory, IPluginFactory<IAsymmetricEncryptor> asymmetricEncryptorFactory, IPluginFactory<ISymmetricEncryptor> symmetricEncryptorFactory)
    {
        _compressorFactory = compressorFactory ?? throw new ArgumentNullException(nameof(compressorFactory));
        _asymmetricEncryptorFactory = asymmetricEncryptorFactory ?? throw new ArgumentNullException(nameof(asymmetricEncryptorFactory));
        _symmetricEncryptorFactory = symmetricEncryptorFactory ?? throw new ArgumentNullException(nameof(symmetricEncryptorFactory));
    }

    /// <summary>
    /// Compresses data and encrypts it using a hybrid encryption approach with a session key.
    /// The data is compressed, encrypted with a symmetric session key, and the session key is encrypted with the server's public key.
    /// </summary>
    /// <param name="serverPublicKey">The RSA public key parameters used to encrypt the session key.</param>
    /// <param name="outputBundle">The output stream where the final event bundle will be written.</param>
    /// <param name="data">The data to compress and encrypt.</param>
    /// <param name="bufferStream">The buffer stream used for intermediate data storage.</param>
    /// <param name="compressionAlgorithm">The name of the compression algorithm to use.</param>
    /// <param name="symmetricEncryptionAlgorithm">The name of the symmetric encryption algorithm to use.</param>
    /// <param name="asymmetricEncryptionAlgorithm">The name of the asymmetric encryption algorithm to use.</param>
    /// <returns>
    /// An <see cref="Encryption"/> object containing the encrypted session key, encrypted data,
    /// and the algorithm names used for encryption and compression.
    /// </returns>
    /// <exception cref="ArgumentException">Thrown when any algorithm parameter is null or empty.</exception>
    /// <remarks>
    /// This method performs the following operations:
    /// <list type="number">
    /// <item><description>Compresses the input data using the specified compression algorithm.</description></item>
    /// <item><description>Generates a random symmetric session key.</description></item>
    /// <item><description>Encrypts the compressed data using the session key and symmetric encryption algorithm.</description></item>
    /// <item><description>Encrypts the session key using the server's public key and asymmetric encryption algorithm.</description></item>
    /// <item><description>Securely zeros the session key from memory after use.</description></item>
    /// </list>
    /// </remarks>
    public async Task<Encryption> CompressAndEncrypt(byte[] serverPublicKey, Stream outputBundle, Stream data, Stream bufferStream, string compressionAlgorithm, string symmetricEncryptionAlgorithm, string asymmetricEncryptionAlgorithm, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(compressionAlgorithm);
        ArgumentException.ThrowIfNullOrEmpty(symmetricEncryptionAlgorithm);
        ArgumentException.ThrowIfNullOrEmpty(asymmetricEncryptionAlgorithm);

        var compressor = _compressorFactory.CreatePlugin(compressionAlgorithm);
        var symmetricEncryptor = _symmetricEncryptorFactory.CreatePlugin(symmetricEncryptionAlgorithm);
        var asymmetricEncryptor = _asymmetricEncryptorFactory.CreatePlugin(asymmetricEncryptionAlgorithm);

        await compressor.Compress(data, bufferStream);
     
        byte[] sessionKey = symmetricEncryptor.GenerateKey();
        try
        {
            byte[] encryptedKey = asymmetricEncryptor.EncryptSessionKey(serverPublicKey, sessionKey);
            await symmetricEncryptor.EncryptStreamAsync(bufferStream, outputBundle, sessionKey, cancellationToken);
            Encryption encryption = new Encryption(
                encryptedKey,
                asymmetricEncryptionAlgorithm,
                symmetricEncryptionAlgorithm,
                compressionAlgorithm);

            return encryption;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sessionKey);
        }
    }
}
