using System.Security.Cryptography;
using CyberAlarm.SyslogRelay.Common.EventBundler.Settings;

namespace CyberAlarm.EventBundler.Plugins.Encryptors;

/// <summary>
/// Provides RSA encryption and decryption using OAEP with SHA-256 padding.
/// </summary>
public sealed class RsaOaepSha256AsymmetricEncryptor : IAsymmetricEncryptor
{
    /// <summary>
    /// Gets the algorithm name used by this encryptor.
    /// </summary>
    public string AlgorithmName => SupportedAlgorithms.Encryptors.RsaOaepSha256;

    /// <summary>
    /// Encrypts a session key using the specified RSA parameters and OAEP SHA-256 padding.
    /// </summary>
    /// <param name="key">The RSA parameters to use for encryption.</param>
    /// <param name="unprotectedKey">The session key to encrypt.</param>
    /// <returns>The encrypted session key as a byte array.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown if <paramref name="unprotectedKey"/> is <c>null</c>.
    /// </exception>
    public byte[] EncryptSessionKey(byte[] key, byte[] unprotectedKey)
    {
        using var rsaKey = RSA.Create();
        rsaKey.ImportRSAPublicKey(key, out _);

        var encryptedKey = rsaKey.Encrypt(unprotectedKey, RSAEncryptionPadding.OaepSHA256);
        return encryptedKey;
    }
}
