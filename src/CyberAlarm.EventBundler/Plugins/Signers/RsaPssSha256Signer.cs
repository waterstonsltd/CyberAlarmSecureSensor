using System.Security.Cryptography;
using CyberAlarm.SyslogRelay.Common.EventBundler.Settings;

namespace CyberAlarm.EventBundler.Plugins.Signers;

/// <summary>
/// Provides RSA-PSS digital signature functionality using SHA-256 hashing algorithm.
/// </summary>
/// <remarks>
/// This signer implements the RSA Probabilistic Signature Scheme (PSS) with SHA-256,
/// providing secure digital signatures for data integrity and authenticity verification.
/// </remarks>
public sealed class RsaPssSha256Signer : ISigner
{
    /// <summary>
    /// Gets the name of the signature algorithm.
    /// </summary>
    /// <value>The algorithm name "RSA-PSS-SHA256".</value>
    public string AlgorithmName => SupportedAlgorithms.Signers.RsaPssSha256;

    public ushort SignatureSize => 512; // 4096 bits / 8 = 512 bytes

    /// <summary>
    /// Signs the specified byte array using RSA-PSS with SHA-256.
    /// </summary>
    /// <param name="key">The RSA private key used for signing.</param>
    /// <param name="dataToSign">The data bytes to be signed.</param>
    /// <returns>A byte array containing the digital signature.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="key"/> or <paramref name="data"/> is null.</exception>
    /// <exception cref="CryptographicException">Thrown when the signing operation fails.</exception>
    public byte[] Sign(byte[] key, Stream dataToSign)
    {
        using var rsaKey = RSA.Create();
        rsaKey.ImportRSAPrivateKey(key, out _);
        return rsaKey.SignData(dataToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
    }
}
